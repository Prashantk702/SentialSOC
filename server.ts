import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

const db = new Database("soc_platform.db");

// Initialize Database Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'Tier-1'
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    source TEXT,
    severity TEXT,
    status TEXT DEFAULT 'New',
    classification TEXT DEFAULT 'Unclassified',
    description TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ioc_data TEXT,
    assigned_to INTEGER,
    FOREIGN KEY(assigned_to) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    ticket_number TEXT UNIQUE,
    notes TEXT,
    escalated_to TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(alert_id) REFERENCES alerts(id)
  );

  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    filename TEXT,
    file_type TEXT,
    data TEXT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
  );
`);

// Seed initial data if empty
const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
if (userCount.count === 0) {
  db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)").run("Prashant K", "password123", "Tier-1");
  
  const sampleAlerts = [
    { title: "Multiple Failed Login Attempts", source: "Firewall", severity: "Medium", description: "Detected 15 failed login attempts from IP 192.168.1.50 within 1 minute.", ioc_data: JSON.stringify({ ip: "192.168.1.50" }) },
    { title: "Suspicious PowerShell Execution", source: "EDR", severity: "High", description: "Encoded PowerShell command executed on Workstation-04.", ioc_data: JSON.stringify({ hostname: "Workstation-04", command: "powershell.exe -enc ..." }) },
    { title: "Potential Phishing Link Clicked", source: "Email Gateway", severity: "Critical", description: "User clicked on a known malicious URL: http://secure-login-update.com/verify", ioc_data: JSON.stringify({ url: "http://secure-login-update.com/verify", user: "j.doe@company.com" }) },
    { title: "Port Scan Detected", source: "IDS", severity: "Low", description: "Inbound port scan detected from external IP 45.33.22.11.", ioc_data: JSON.stringify({ ip: "45.33.22.11" }) },
    { title: "Unauthorized File Access", source: "File Server", severity: "Medium", description: "User 'guest' attempted to access sensitive HR folder.", ioc_data: JSON.stringify({ user: "guest", path: "/shares/HR/salaries.xlsx" }) }
  ];

  const insertAlert = db.prepare("INSERT INTO alerts (title, source, severity, description, ioc_data) VALUES (?, ?, ?, ?, ?)");
  sampleAlerts.forEach(a => insertAlert.run(a.title, a.source, a.severity, a.description, a.ioc_data));
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '50mb' }));
  const PORT = 3000;

  // API Routes
  app.get("/api/alerts", (req, res) => {
    const alerts = db.prepare("SELECT * FROM alerts ORDER BY timestamp DESC").all();
    res.json(alerts);
  });

  app.get("/api/alerts/:id", (req, res) => {
    const alert = db.prepare("SELECT * FROM alerts WHERE id = ?").get(req.params.id);
    res.json(alert);
  });

  app.patch("/api/alerts/:id", (req, res) => {
    const { status, classification, severity } = req.body;
    const updates = [];
    const params = [];
    if (status) { updates.push("status = ?"); params.push(status); }
    if (classification) { updates.push("classification = ?"); params.push(classification); }
    if (severity) { updates.push("severity = ?"); params.push(severity); }
    params.push(req.params.id);

    db.prepare(`UPDATE alerts SET ${updates.join(", ")} WHERE id = ?`).run(...params);
    
    // Log activity
    db.prepare("INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)").run(1, "Update Alert", `Alert ID ${req.params.id} updated: ${JSON.stringify(req.body)}`);
    
    res.json({ success: true });
  });

  app.post("/api/incidents", (req, res) => {
    const { alert_id, notes } = req.body;
    const ticket_number = `INC-${Date.now()}`;
    const result = db.prepare("INSERT INTO incidents (alert_id, ticket_number, notes) VALUES (?, ?, ?)").run(alert_id, ticket_number, notes);
    
    db.prepare("UPDATE alerts SET status = 'In Progress' WHERE id = ?").run(alert_id);
    db.prepare("INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)").run(1, "Create Incident", `Incident ${ticket_number} created for alert ${alert_id}`);
    
    res.json({ id: result.lastInsertRowid, ticket_number });
  });

  app.get("/api/incidents/:alertId", (req, res) => {
    const incident = db.prepare("SELECT * FROM incidents WHERE alert_id = ?").get(req.params.alertId);
    res.json(incident || null);
  });

  app.post("/api/incidents/:id/escalate", (req, res) => {
    const { escalated_to } = req.body;
    db.prepare("UPDATE incidents SET escalated_to = ? WHERE id = ?").run(escalated_to, req.params.id);
    db.prepare("INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)").run(1, "Escalate Incident", `Incident ID ${req.params.id} escalated to ${escalated_to}`);
    res.json({ success: true });
  });

  app.post("/api/evidence", (req, res) => {
    const { incident_id, filename, file_type, data } = req.body;
    db.prepare("INSERT INTO evidence (incident_id, filename, file_type, data) VALUES (?, ?, ?, ?)").run(incident_id, filename, file_type, data);
    res.json({ success: true });
  });

  app.get("/api/evidence/:incidentId", (req, res) => {
    const evidence = db.prepare("SELECT id, filename, file_type, uploaded_at FROM evidence WHERE incident_id = ?").all();
    res.json(evidence);
  });

  app.get("/api/logs", (req, res) => {
    const logs = db.prepare("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 100").all();
    res.json(logs);
  });

  app.get("/api/stats", (req, res) => {
    const totalAlerts = db.prepare("SELECT COUNT(*) as count FROM alerts").get() as any;
    const severityDist = db.prepare("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity").all();
    const sourceDist = db.prepare("SELECT source, COUNT(*) as count FROM alerts GROUP BY source").all();
    const statusDist = db.prepare("SELECT status, COUNT(*) as count FROM alerts GROUP BY status").all();
    
    res.json({
      total: totalAlerts.count,
      severity: severityDist,
      sources: sourceDist,
      status: statusDist
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
    app.get("*", (req, res) => res.sendFile(path.resolve("dist/index.html")));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
