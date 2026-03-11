/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Mail, 
  Search, 
  BarChart3, 
  FileText, 
  History, 
  User, 
  ChevronRight, 
  Filter, 
  CheckCircle2, 
  XCircle, 
  Info,
  ExternalLink,
  Upload,
  Download,
  ArrowUpRight,
  Clock,
  Activity
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell,
  LineChart,
  Line
} from 'recharts';
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';
import { format } from 'date-fns';
import { motion, AnimatePresence } from 'motion/react';

// --- Types ---

type Severity = 'Low' | 'Medium' | 'High' | 'Critical';
type Status = 'New' | 'In Progress' | 'Closed';
type Classification = 'Unclassified' | 'True Positive' | 'False Positive' | 'Informational';

interface Alert {
  id: number;
  title: string;
  source: string;
  severity: Severity;
  status: Status;
  classification: Classification;
  description: string;
  timestamp: string;
  ioc_data: string;
}

interface Incident {
  id: number;
  alert_id: number;
  ticket_number: string;
  notes: string;
  escalated_to: string | null;
  created_at: string;
}

interface Stats {
  total: number;
  severity: { severity: string; count: number }[];
  sources: { source: string; count: number }[];
  status: { status: string; count: number }[];
}

interface ActivityLog {
  id: number;
  action: string;
  details: string;
  timestamp: string;
}

// --- Components ---

const Badge = ({ children, className, ...props }: { children: React.ReactNode; className?: string; [key: string]: any }) => (
  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${className}`} {...props}>
    {children}
  </span>
);

const SeverityBadge = ({ severity }: { severity: Severity }) => {
  const colors = {
    Low: 'bg-blue-100 text-blue-700 border border-blue-200',
    Medium: 'bg-yellow-100 text-yellow-700 border border-yellow-200',
    High: 'bg-orange-100 text-orange-700 border border-orange-200',
    Critical: 'bg-red-100 text-red-700 border border-red-200',
  };
  return <Badge className={colors[severity]}>{severity}</Badge>;
};

const StatusBadge = ({ status }: { status: Status }) => {
  const colors = {
    New: 'bg-indigo-100 text-indigo-700',
    'In Progress': 'bg-blue-100 text-blue-700',
    Closed: 'bg-green-100 text-green-700',
  };
  return <Badge className={colors[status]}>{status}</Badge>;
};

// --- Main App ---

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'phishing' | 'analytics' | 'logs'>('dashboard');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('All');

  // Phishing Analyzer State
  const [emailContent, setEmailContent] = useState('');
  const [phishingResult, setPhishingResult] = useState<any>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || !e.target.files[0] || !incident) return;
    const file = e.target.files[0];
    const reader = new FileReader();
    reader.onload = async (event) => {
      const base64 = event.target?.result as string;
      await fetch('/api/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incident.id,
          filename: file.name,
          file_type: file.type,
          data: base64
        })
      });
      alert('Evidence uploaded successfully');
    };
    reader.readAsDataURL(file);
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const [alertsRes, statsRes, logsRes] = await Promise.all([
        fetch('/api/alerts'),
        fetch('/api/stats'),
        fetch('/api/logs')
      ]);
      setAlerts(await alertsRes.json());
      setStats(await statsRes.json());
      setLogs(await logsRes.json());
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAlertClick = async (alert: Alert) => {
    setSelectedAlert(alert);
    const res = await fetch(`/api/incidents/${alert.id}`);
    const data = await res.json();
    setIncident(data);
  };

  const updateAlert = async (id: number, data: Partial<Alert>) => {
    await fetch(`/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    fetchData();
    if (selectedAlert?.id === id) {
      setSelectedAlert({ ...selectedAlert, ...data } as Alert);
    }
  };

  const createIncident = async (alertId: number, notes: string) => {
    const res = await fetch('/api/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId, notes })
    });
    const data = await res.json();
    setIncident({
      id: data.id,
      alert_id: alertId,
      ticket_number: data.ticket_number,
      notes,
      escalated_to: null,
      created_at: new Date().toISOString()
    });
    fetchData();
  };

  const escalateIncident = async (incidentId: number, tier: string) => {
    await fetch(`/api/incidents/${incidentId}/escalate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ escalated_to: tier })
    });
    setIncident(prev => prev ? { ...prev, escalated_to: tier } : null);
    fetchData();
  };

  const analyzeEmail = () => {
    const iocs = {
      ips: emailContent.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [],
      urls: emailContent.match(/https?:\/\/[^\s]+/g) || [],
      domains: emailContent.match(/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/g) || [],
    };

    const suspiciousKeywords = ['urgent', 'password', 'verify', 'account', 'suspended', 'login', 'bank', 'official'];
    const foundKeywords = suspiciousKeywords.filter(k => emailContent.toLowerCase().includes(k));
    
    let score = 0;
    if (iocs.urls.length > 0) score += 40;
    if (foundKeywords.length > 2) score += 30;
    if (emailContent.length < 100 && emailContent.length > 0) score += 20;

    setPhishingResult({
      score: Math.min(score, 100),
      iocs,
      keywords: foundKeywords,
      verdict: score > 60 ? 'Malicious' : score > 30 ? 'Suspicious' : 'Clean'
    });
  };

  const generateReport = () => {
    if (!selectedAlert || !incident) return;
    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text('SOC Incident Report', 105, 20, { align: 'center' });
    
    doc.setFontSize(12);
    doc.text(`Ticket Number: ${incident.ticket_number}`, 20, 40);
    doc.text(`Alert Title: ${selectedAlert.title}`, 20, 50);
    doc.text(`Severity: ${selectedAlert.severity}`, 20, 60);
    doc.text(`Source: ${selectedAlert.source}`, 20, 70);
    doc.text(`Timestamp: ${format(new Date(selectedAlert.timestamp), 'PPP p')}`, 20, 80);
    
    doc.text('Investigation Notes:', 20, 100);
    doc.setFont('helvetica', 'italic');
    doc.text(incident.notes, 20, 110, { maxWidth: 170 });
    
    doc.save(`${incident.ticket_number}-report.pdf`);
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const matchesSearch = a.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                            a.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSeverity = filterSeverity === 'All' || a.severity === filterSeverity;
      return matchesSearch && matchesSeverity;
    });
  }, [alerts, searchQuery, filterSeverity]);

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 font-sans flex">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 text-white flex flex-col fixed h-full z-20">
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="bg-indigo-500 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <span className="font-bold text-xl tracking-tight">SentinelSOC</span>
        </div>
        
        <nav className="flex-1 p-4 space-y-2">
          <button 
            onClick={() => setActiveTab('dashboard')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'dashboard' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}
          >
            <BarChart3 className="w-5 h-5" />
            <span className="font-medium">Dashboard</span>
          </button>
          <button 
            onClick={() => setActiveTab('alerts')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'alerts' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}
          >
            <AlertTriangle className="w-5 h-5" />
            <span className="font-medium">Alert Queue</span>
          </button>
          <button 
            onClick={() => setActiveTab('phishing')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'phishing' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}
          >
            <Mail className="w-5 h-5" />
            <span className="font-medium">Phishing Analyzer</span>
          </button>
          <button 
            onClick={() => setActiveTab('analytics')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'analytics' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}
          >
            <Activity className="w-5 h-5" />
            <span className="font-medium">SOC Analytics</span>
          </button>
          <button 
            onClick={() => setActiveTab('logs')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'logs' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}
          >
            <History className="w-5 h-5" />
            <span className="font-medium">Activity Logs</span>
          </button>
        </nav>

        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-xl">
            <div className="w-10 h-10 rounded-full bg-indigo-500 flex items-center justify-center font-bold">PK</div>
            <div className="overflow-hidden">
              <p className="text-sm font-semibold truncate">Prashant K</p>
              <p className="text-xs text-slate-400">Tier-1 Analyst</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 ml-64 p-8">
        <header className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 capitalize">{activeTab}</h1>
            <p className="text-slate-500 text-sm">Welcome back, Prashant K. Monitoring active.</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input 
                type="text" 
                placeholder="Search alerts, IPs, tickets..." 
                className="pl-10 pr-4 py-2 bg-white border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all w-64"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button className="p-2 bg-white border border-slate-200 rounded-xl hover:bg-slate-50 transition-all relative">
              <div className="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></div>
              <User className="w-5 h-5 text-slate-600" />
            </button>
          </div>
        </header>

        {/* Dashboard View */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <div className="flex justify-between items-start mb-4">
                  <div className="p-3 bg-indigo-50 rounded-xl">
                    <AlertTriangle className="w-6 h-6 text-indigo-600" />
                  </div>
                  <span className="text-xs font-medium text-green-600 bg-green-50 px-2 py-1 rounded-lg">+12%</span>
                </div>
                <h3 className="text-slate-500 text-sm font-medium">Total Alerts</h3>
                <p className="text-3xl font-bold mt-1">{stats?.total || 0}</p>
              </div>
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <div className="flex justify-between items-start mb-4">
                  <div className="p-3 bg-red-50 rounded-xl">
                    <Shield className="w-6 h-6 text-red-600" />
                  </div>
                  <span className="text-xs font-medium text-red-600 bg-red-50 px-2 py-1 rounded-lg">High Risk</span>
                </div>
                <h3 className="text-slate-500 text-sm font-medium">Critical Alerts</h3>
                <p className="text-3xl font-bold mt-1">{stats?.severity.find(s => s.severity === 'Critical')?.count || 0}</p>
              </div>
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <div className="flex justify-between items-start mb-4">
                  <div className="p-3 bg-blue-50 rounded-xl">
                    <Clock className="w-6 h-6 text-blue-600" />
                  </div>
                  <span className="text-xs font-medium text-slate-500 bg-slate-50 px-2 py-1 rounded-lg">Avg 14m</span>
                </div>
                <h3 className="text-slate-500 text-sm font-medium">Pending Review</h3>
                <p className="text-3xl font-bold mt-1">{stats?.status.find(s => s.status === 'New')?.count || 0}</p>
              </div>
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <div className="flex justify-between items-start mb-4">
                  <div className="p-3 bg-green-50 rounded-xl">
                    <CheckCircle2 className="w-6 h-6 text-green-600" />
                  </div>
                  <span className="text-xs font-medium text-green-600 bg-green-50 px-2 py-1 rounded-lg">98.2%</span>
                </div>
                <h3 className="text-slate-500 text-sm font-medium">Resolution Rate</h3>
                <p className="text-3xl font-bold mt-1">{stats?.status.find(s => s.status === 'Closed')?.count || 0}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Recent Alerts */}
              <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                <div className="p-6 border-b border-slate-100 flex justify-between items-center">
                  <h2 className="font-bold text-lg">Recent Security Alerts</h2>
                  <button onClick={() => setActiveTab('alerts')} className="text-indigo-600 text-sm font-semibold hover:underline flex items-center gap-1">
                    View All <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                      <tr>
                        <th className="px-6 py-4 font-semibold">Alert</th>
                        <th className="px-6 py-4 font-semibold">Severity</th>
                        <th className="px-6 py-4 font-semibold">Source</th>
                        <th className="px-6 py-4 font-semibold">Time</th>
                        <th className="px-6 py-4 font-semibold">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {alerts.slice(0, 5).map((alert) => (
                        <tr key={alert.id} className="hover:bg-slate-50 transition-all cursor-pointer" onClick={() => { setSelectedAlert(alert); setActiveTab('alerts'); }}>
                          <td className="px-6 py-4">
                            <p className="font-semibold text-sm">{alert.title}</p>
                            <p className="text-xs text-slate-400 truncate max-w-[200px]">{alert.description}</p>
                          </td>
                          <td className="px-6 py-4"><SeverityBadge severity={alert.severity} /></td>
                          <td className="px-6 py-4 text-sm text-slate-600">{alert.source}</td>
                          <td className="px-6 py-4 text-xs text-slate-400">{format(new Date(alert.timestamp), 'HH:mm')}</td>
                          <td className="px-6 py-4"><StatusBadge status={alert.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Attack Distribution */}
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
                <h2 className="font-bold text-lg mb-6">Severity Distribution</h2>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={stats?.severity || []}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="count"
                        nameKey="severity"
                      >
                        {stats?.severity.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-4 space-y-2">
                  {stats?.severity.map((s, i) => (
                    <div key={s.severity} className="flex justify-between items-center text-sm">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[i % COLORS.length] }}></div>
                        <span className="text-slate-600">{s.severity}</span>
                      </div>
                      <span className="font-bold">{s.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Alerts Queue View */}
        {activeTab === 'alerts' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[calc(100vh-180px)]">
            {/* Alert List */}
            <div className="lg:col-span-4 bg-white rounded-2xl border border-slate-200 shadow-sm flex flex-col overflow-hidden">
              <div className="p-4 border-b border-slate-100 space-y-4">
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-slate-400" />
                  <select 
                    className="bg-transparent text-sm font-semibold focus:outline-none"
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
                {filteredAlerts.map(alert => (
                  <div 
                    key={alert.id} 
                    onClick={() => handleAlertClick(alert)}
                    className={`p-4 cursor-pointer transition-all hover:bg-slate-50 ${selectedAlert?.id === alert.id ? 'bg-indigo-50 border-l-4 border-indigo-500' : ''}`}
                  >
                    <div className="flex justify-between items-start mb-1">
                      <SeverityBadge severity={alert.severity} />
                      <span className="text-[10px] text-slate-400 uppercase font-bold">{format(new Date(alert.timestamp), 'MMM d, HH:mm')}</span>
                    </div>
                    <h3 className="font-bold text-sm text-slate-900 mb-1">{alert.title}</h3>
                    <p className="text-xs text-slate-500 line-clamp-2">{alert.description}</p>
                    <div className="mt-2 flex items-center gap-2">
                      <span className="text-[10px] bg-slate-100 px-1.5 py-0.5 rounded text-slate-500 font-medium">{alert.source}</span>
                      <StatusBadge status={alert.status} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Alert Detail */}
            <div className="lg:col-span-8 bg-white rounded-2xl border border-slate-200 shadow-sm flex flex-col overflow-hidden">
              {selectedAlert ? (
                <div className="flex-1 overflow-y-auto p-8">
                  <div className="flex justify-between items-start mb-8">
                    <div>
                      <div className="flex items-center gap-3 mb-2">
                        <SeverityBadge severity={selectedAlert.severity} />
                        <StatusBadge status={selectedAlert.status} />
                        <Badge className="bg-slate-100 text-slate-600">{selectedAlert.source}</Badge>
                      </div>
                      <h2 className="text-3xl font-bold text-slate-900">{selectedAlert.title}</h2>
                      <p className="text-slate-500 mt-1">Alert ID: #{selectedAlert.id} • Detected at {format(new Date(selectedAlert.timestamp), 'PPP p')}</p>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={generateReport} disabled={!incident} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm font-semibold hover:bg-slate-50 disabled:opacity-50">
                        <Download className="w-4 h-4" /> Export PDF
                      </button>
                      {selectedAlert.status !== 'Closed' && (
                        <button 
                          onClick={() => updateAlert(selectedAlert.id, { status: 'Closed' })}
                          className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-xl text-sm font-semibold hover:bg-green-700 shadow-lg shadow-green-500/20"
                        >
                          <CheckCircle2 className="w-4 h-4" /> Close Alert
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
                    <div className="md:col-span-2 space-y-8">
                      <section>
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Description</h3>
                        <div className="bg-slate-50 p-6 rounded-2xl border border-slate-100 text-slate-700 leading-relaxed">
                          {selectedAlert.description}
                        </div>
                      </section>

                      <section>
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Indicators of Compromise (IOCs)</h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          {Object.entries(JSON.parse(selectedAlert.ioc_data || '{}')).map(([key, value]) => (
                            <div key={key} className="bg-white border border-slate-200 p-4 rounded-xl flex justify-between items-center group">
                              <div>
                                <p className="text-[10px] font-bold text-slate-400 uppercase">{key}</p>
                                <p className="text-sm font-mono font-medium text-slate-700">{String(value)}</p>
                              </div>
                              <button className="p-2 text-slate-400 hover:text-indigo-600 opacity-0 group-hover:opacity-100 transition-all">
                                <ExternalLink className="w-4 h-4" />
                              </button>
                            </div>
                          ))}
                        </div>
                      </section>

                      <section>
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Investigation & Actions</h3>
                        {!incident ? (
                          <div className="bg-indigo-50 border border-indigo-100 p-8 rounded-2xl text-center">
                            <Info className="w-8 h-8 text-indigo-500 mx-auto mb-3" />
                            <h4 className="font-bold text-indigo-900">No Incident Ticket Created</h4>
                            <p className="text-indigo-700 text-sm mb-6">This alert needs investigation. Create a ticket to start tracking actions.</p>
                            <button 
                              onClick={() => createIncident(selectedAlert.id, "Initial investigation started. Reviewing logs...")}
                              className="px-6 py-3 bg-indigo-600 text-white rounded-xl font-bold hover:bg-indigo-700 shadow-lg shadow-indigo-500/20 transition-all"
                            >
                              Create Incident Ticket
                            </button>
                          </div>
                        ) : (
                          <div className="space-y-6">
                            <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden">
                              <div className="bg-slate-50 px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                                <div className="flex items-center gap-2">
                                  <FileText className="w-4 h-4 text-slate-400" />
                                  <span className="font-bold text-sm">{incident.ticket_number}</span>
                                </div>
                                <span className="text-xs text-slate-500">Created {format(new Date(incident.created_at), 'PPP')}</span>
                              </div>
                              <div className="p-6">
                                <textarea 
                                  className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 min-h-[120px]"
                                  value={incident.notes}
                                  onChange={(e) => setIncident({ ...incident, notes: e.target.value })}
                                  placeholder="Add investigation notes here..."
                                />
                                <div className="mt-4 flex justify-between items-center">
                                  <div className="flex items-center gap-4">
                                    <label className="text-xs font-bold text-indigo-600 hover:underline flex items-center gap-1 cursor-pointer">
                                      <Upload className="w-3 h-3" /> Attach Evidence
                                      <input type="file" className="hidden" onChange={handleFileUpload} />
                                    </label>
                                  </div>
                                  <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-bold hover:bg-indigo-700">Save Notes</button>
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-4 p-4 bg-orange-50 border border-orange-100 rounded-2xl">
                              <div className="p-2 bg-orange-100 rounded-lg">
                                <ArrowUpRight className="w-5 h-5 text-orange-600" />
                              </div>
                              <div className="flex-1">
                                <p className="text-sm font-bold text-orange-900">Escalate to Tier-2</p>
                                <p className="text-xs text-orange-700">Need expert review? Escalate this incident to senior analysts.</p>
                              </div>
                              {incident.escalated_to ? (
                                <Badge className="bg-orange-200 text-orange-800">Escalated to {incident.escalated_to}</Badge>
                              ) : (
                                <button 
                                  onClick={() => escalateIncident(incident.id, 'Tier-2')}
                                  className="px-4 py-2 bg-orange-600 text-white rounded-lg text-xs font-bold hover:bg-orange-700"
                                >
                                  Escalate Now
                                </button>
                              )}
                            </div>
                          </div>
                        )}
                      </section>
                    </div>

                    <div className="space-y-6">
                      <section>
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Classification</h3>
                        <div className="space-y-2">
                          {['True Positive', 'False Positive', 'Informational'].map(c => (
                            <button 
                              key={c}
                              onClick={() => updateAlert(selectedAlert.id, { classification: c as any })}
                              className={`w-full text-left px-4 py-3 rounded-xl border text-sm font-medium transition-all ${selectedAlert.classification === c ? 'bg-indigo-600 text-white border-indigo-600 shadow-lg shadow-indigo-500/20' : 'bg-white text-slate-600 border-slate-200 hover:border-indigo-300'}`}
                            >
                              {c}
                            </button>
                          ))}
                        </div>
                      </section>

                      <section>
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Threat Intel Lookup</h3>
                        <div className="bg-slate-900 text-slate-300 p-4 rounded-2xl font-mono text-[11px] leading-relaxed">
                          <p className="text-green-400">$ sentinel-intel --lookup {JSON.parse(selectedAlert.ioc_data || '{}').ip || 'IOC'}</p>
                          <p className="mt-2">Searching VirusTotal... [FOUND]</p>
                          <p>Searching AlienVault... [FOUND]</p>
                          <p>Searching CrowdStrike... [CLEAN]</p>
                          <p className="mt-2 text-red-400">Reputation: MALICIOUS (8/64)</p>
                          <p>Category: Command & Control</p>
                        </div>
                      </section>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-400 p-8 text-center">
                  <div className="w-20 h-20 bg-slate-50 rounded-full flex items-center justify-center mb-4">
                    <AlertTriangle className="w-10 h-10" />
                  </div>
                  <h3 className="text-lg font-bold text-slate-900">No Alert Selected</h3>
                  <p className="max-w-xs mt-2">Select an alert from the queue to start your investigation and triage process.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Phishing Analyzer View */}
        {activeTab === 'phishing' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-6">
              <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
                <h2 className="text-xl font-bold mb-4">Analyze Suspicious Email</h2>
                <p className="text-slate-500 text-sm mb-6">Paste the raw email content or headers below to detect malicious indicators and phishing attempts.</p>
                <textarea 
                  className="w-full bg-slate-50 border border-slate-200 rounded-2xl p-6 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 min-h-[400px] font-mono"
                  placeholder="Paste email content here..."
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                />
                <button 
                  onClick={analyzeEmail}
                  className="w-full mt-6 py-4 bg-indigo-600 text-white rounded-2xl font-bold hover:bg-indigo-700 shadow-lg shadow-indigo-500/20 transition-all flex items-center justify-center gap-2"
                >
                  <Search className="w-5 h-5" /> Run Security Analysis
                </button>
              </div>
            </div>

            <div className="space-y-6">
              {phishingResult ? (
                <motion.div 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm"
                >
                  <div className="flex justify-between items-center mb-8">
                    <h2 className="text-xl font-bold">Analysis Results</h2>
                    <Badge className={
                      phishingResult.verdict === 'Malicious' ? 'bg-red-100 text-red-700 text-sm px-4 py-1' :
                      phishingResult.verdict === 'Suspicious' ? 'bg-orange-100 text-orange-700 text-sm px-4 py-1' :
                      'bg-green-100 text-green-700 text-sm px-4 py-1'
                    }>
                      {phishingResult.verdict}
                    </Badge>
                  </div>

                  <div className="mb-8">
                    <div className="flex justify-between items-end mb-2">
                      <span className="text-sm font-bold text-slate-500 uppercase">Risk Score</span>
                      <span className="text-2xl font-black text-slate-900">{phishingResult.score}/100</span>
                    </div>
                    <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${phishingResult.score}%` }}
                        className={`h-full ${phishingResult.score > 60 ? 'bg-red-500' : phishingResult.score > 30 ? 'bg-orange-500' : 'bg-green-500'}`}
                      />
                    </div>
                  </div>

                  <div className="space-y-6">
                    <section>
                      <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Extracted IOCs</h3>
                      <div className="space-y-2">
                        {phishingResult.iocs.urls.length > 0 && (
                          <div className="p-4 bg-red-50 border border-red-100 rounded-xl">
                            <p className="text-[10px] font-bold text-red-400 uppercase mb-2">Malicious URLs</p>
                            {phishingResult.iocs.urls.map((url: string, i: number) => (
                              <p key={i} className="text-xs font-mono text-red-700 break-all">{url}</p>
                            ))}
                          </div>
                        )}
                        {phishingResult.iocs.ips.length > 0 && (
                          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
                            <p className="text-[10px] font-bold text-slate-400 uppercase mb-2">Sender IPs</p>
                            {phishingResult.iocs.ips.map((ip: string, i: number) => (
                              <p key={i} className="text-xs font-mono text-slate-700">{ip}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    </section>

                    <section>
                      <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Suspicious Keywords</h3>
                      <div className="flex flex-wrap gap-2">
                        {phishingResult.keywords.map((k: string) => (
                          <Badge key={k} className="bg-orange-50 text-orange-700 border border-orange-100">{k}</Badge>
                        ))}
                        {phishingResult.keywords.length === 0 && <p className="text-sm text-slate-400 italic">No suspicious keywords found.</p>}
                      </div>
                    </section>

                    <div className="pt-6 border-t border-slate-100">
                      <button className="w-full py-3 bg-slate-900 text-white rounded-xl font-bold hover:bg-slate-800 transition-all">
                        Generate Phishing Alert
                      </button>
                    </div>
                  </div>
                </motion.div>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-slate-400 bg-slate-50/50 rounded-2xl border-2 border-dashed border-slate-200 p-12 text-center">
                  <Mail className="w-12 h-12 mb-4 opacity-20" />
                  <h3 className="text-lg font-bold text-slate-900">Ready for Analysis</h3>
                  <p className="max-w-xs mt-2">Paste email content on the left to begin the automated phishing detection process.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Analytics View */}
        {activeTab === 'analytics' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
                <h2 className="text-xl font-bold mb-8">Attack Vectors by Source</h2>
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={stats?.sources || []}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                      <XAxis dataKey="source" axisLine={false} tickLine={false} tick={{ fill: '#64748b', fontSize: 12 }} />
                      <YAxis axisLine={false} tickLine={false} tick={{ fill: '#64748b', fontSize: 12 }} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '12px', color: '#fff' }}
                        itemStyle={{ color: '#fff' }}
                      />
                      <Bar dataKey="count" fill="#6366f1" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
                <h2 className="text-xl font-bold mb-8">Alert Resolution Status</h2>
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={stats?.status || []}
                        cx="50%"
                        cy="50%"
                        innerRadius={80}
                        outerRadius={100}
                        paddingAngle={5}
                        dataKey="count"
                        nameKey="status"
                      >
                        {stats?.status.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={['#6366f1', '#3b82f6', '#10b981'][index % 3]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
              <h2 className="text-xl font-bold mb-8">Alert Volume (Last 24 Hours)</h2>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={[
                    { time: '00:00', count: 4 },
                    { time: '04:00', count: 2 },
                    { time: '08:00', count: 12 },
                    { time: '12:00', count: 8 },
                    { time: '16:00', count: 15 },
                    { time: '20:00', count: 6 },
                    { time: '23:59', count: 9 },
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                    <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#64748b', fontSize: 12 }} />
                    <YAxis axisLine={false} tickLine={false} tick={{ fill: '#64748b', fontSize: 12 }} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '12px', color: '#fff' }}
                    />
                    <Line type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={3} dot={{ fill: '#6366f1', strokeWidth: 2, r: 4 }} activeDot={{ r: 6 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* Logs View */}
        {activeTab === 'logs' && (
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-6 border-b border-slate-100">
              <h2 className="font-bold text-lg">Security Activity Logs</h2>
              <p className="text-slate-500 text-sm">Audit trail of all analyst actions and system events.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                  <tr>
                    <th className="px-6 py-4 font-semibold">Timestamp</th>
                    <th className="px-6 py-4 font-semibold">Action</th>
                    <th className="px-6 py-4 font-semibold">Details</th>
                    <th className="px-6 py-4 font-semibold">Analyst</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-50 transition-all">
                      <td className="px-6 py-4 text-xs text-slate-400 whitespace-nowrap">{format(new Date(log.timestamp), 'MMM d, HH:mm:ss')}</td>
                      <td className="px-6 py-4">
                        <Badge className={
                          log.action.includes('Escalate') ? 'bg-orange-100 text-orange-700' :
                          log.action.includes('Create') ? 'bg-green-100 text-green-700' :
                          'bg-blue-100 text-blue-700'
                        }>
                          {log.action}
                        </Badge>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-600 font-mono">{log.details}</td>
                      <td className="px-6 py-4 text-sm text-slate-500">Prashant K</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
