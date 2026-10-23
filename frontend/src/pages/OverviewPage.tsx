import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  PlusCircle,
  ExternalLink,
  Flame,
  Activity,
  Layers,
  Database,
  RefreshCw,
  Globe,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  LineChart,
  Line,
  CartesianGrid,
} from 'recharts';
import { api } from '../services/api';
import { DashboardSummary } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFORMATIONAL: '#64748b',
};

export const OverviewPage: React.FC = () => {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getDashboardSummary();
      setData(res);
    } catch (err: any) {
      setError(err?.response?.data?.message || err?.message || 'Failed to connect to SentinelScan backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  const handleSeedDemo = async () => {
    try {
      setSeeding(true);
      await api.seedDemoData();
      await fetchSummary();
    } catch (err: any) {
      alert('Failed to seed demo records: ' + (err?.message || 'Unknown error'));
    } finally {
      setSeeding(false);
    }
  };

  if (loading && !data) {
    return <LoadingSpinner label="Compiling security dashboard telemetry..." size="lg" />;
  }

  if (error) {
    return (
      <div className="p-6 rounded-2xl border border-red-500/40 bg-gradient-to-br from-red-950/40 to-slate-950/80 backdrop-blur-xl text-red-300 shadow-xl shadow-red-950/20">
        <div className="flex items-center gap-3 mb-2">
          <ShieldAlert className="w-6 h-6 text-red-400" />
          <h3 className="font-bold text-lg text-white">Backend Connection Error</h3>
        </div>
        <p className="text-sm mb-4 text-slate-300">{error}</p>
        <button
          onClick={fetchSummary}
          className="px-4 py-2 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white transition-all shadow-md shadow-red-600/30"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const severityChartData = data
    ? [
        { name: 'Critical', count: data.critical_findings, color: SEVERITY_COLORS.CRITICAL },
        { name: 'High', count: data.high_findings, color: SEVERITY_COLORS.HIGH },
        { name: 'Medium', count: data.medium_findings, color: SEVERITY_COLORS.MEDIUM },
        { name: 'Low', count: data.low_findings, color: SEVERITY_COLORS.LOW },
        { name: 'Info', count: data.info_findings, color: SEVERITY_COLORS.INFORMATIONAL },
      ]
    : [];

  const isBrandNew = !data || (data.total_scans === 0 && data.total_findings === 0);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 shadow-sm shadow-sky-500/20">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
                Security Posture & Telemetry
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time defensive vulnerability analytics and transport layer hygiene metrics.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={fetchSummary}
            className="p-2.5 rounded-xl border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white hover:bg-slate-800/80 transition-all shadow-sm"
            title="Refresh dashboard metrics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleSeedDemo}
            disabled={seeding}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-xl border border-slate-700/80 bg-slate-900/80 hover:bg-slate-800 text-slate-200 transition-all shadow-sm hover:border-slate-600"
          >
            <Database className="w-3.5 h-3.5 text-sky-400" />
            <span>{seeding ? 'Generating Mock Scans...' : 'Seed Demo Data'}</span>
          </button>

          <Link
            to="/scans/new"
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl bg-gradient-to-r from-sky-500 to-cyan-500 hover:from-sky-400 hover:to-cyan-400 text-slate-950 transition-all shadow-md shadow-sky-500/25 hover:shadow-sky-500/40 hover:-translate-y-0.5"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Launch New Scan</span>
          </Link>
        </div>
      </div>

      {isBrandNew ? (
        <EmptyState
          title="No Security Scans Run Yet"
          description="Submit a website URL to begin automated defensive assessment of HTTP headers, cookies, CORS, and TLS certificates."
          actionText="Start Your First Scan"
          onAction={() => (window.location.href = '/scans/new')}
          icon={<ShieldAlert className="w-12 h-12 text-sky-400" />}
        />
      ) : (
        <>
          {/* Key Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Total Scans */}
            <div className="cyber-card p-5 relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-24 h-24 bg-sky-500/5 rounded-full blur-2xl group-hover:bg-sky-500/10 transition-all pointer-events-none" />
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Scans</span>
                <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400">
                  <Activity className="w-4 h-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-white tracking-tight">{data?.total_scans}</div>
              <div className="text-xs text-emerald-400 font-medium flex items-center gap-1.5 mt-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span>{data?.completed_scans} completed successfully</span>
              </div>
            </div>

            {/* Card 2: Total Findings */}
            <div className="cyber-card p-5 relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition-all pointer-events-none" />
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Findings</span>
                <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
                  <Layers className="w-4 h-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-white tracking-tight">{data?.total_findings}</div>
              <div className="text-xs text-slate-400 mt-2">
                Across {data?.completed_scans} analyzed targets
              </div>
            </div>

            {/* Card 3: Critical & High */}
            <div className="cyber-card p-5 relative overflow-hidden group border-rose-500/30 bg-gradient-to-br from-slate-900/80 to-rose-950/20">
              <div className="absolute top-0 right-0 w-24 h-24 bg-rose-500/10 rounded-full blur-2xl group-hover:bg-rose-500/15 transition-all pointer-events-none" />
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-rose-300">High & Critical Risk</span>
                <div className="p-2 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-400">
                  <Flame className="w-4 h-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-rose-400 tracking-tight">
                {(data?.critical_findings || 0) + (data?.high_findings || 0)}
              </div>
              <div className="text-xs text-rose-300/80 font-medium flex items-center gap-1.5 mt-2">
                <span>{data?.critical_findings} Critical</span>
                <span>•</span>
                <span>{data?.high_findings} High Priority</span>
              </div>
            </div>

            {/* Card 4: Latest Target */}
            <div className="cyber-card p-5 relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl group-hover:bg-emerald-500/10 transition-all pointer-events-none" />
              <div className="flex items-center justify-between text-slate-400 mb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Latest Target</span>
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <Globe className="w-4 h-4" />
                </div>
              </div>
              <div className="text-sm font-bold text-slate-200 truncate font-mono">
                {data?.recent_scans?.[0]?.target_hostname || 'None'}
              </div>
              <div className="mt-2 flex items-center gap-2">
                {data?.recent_scans?.[0] ? (
                  <StatusBadge status={data.recent_scans[0].status} size="sm" />
                ) : (
                  <span className="text-xs text-slate-500">No activity</span>
                )}
                <span className="text-[11px] text-slate-400">
                  {data?.recent_scans?.[0]?.total_findings ?? 0} findings
                </span>
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Severity Distribution */}
            <div className="cyber-card p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-sky-400" />
                    Findings by Severity Level
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Distribution of security observations classified by impact severity.
                  </p>
                </div>
              </div>

              <div className="h-64 w-full" style={{ minHeight: '260px' }}>
                <ResponsiveContainer width="100%" height={260} minWidth={100}>
                  <BarChart data={severityChartData} margin={{ top: 15, right: 15, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                    <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '12px',
                        color: '#f8fafc',
                        fontSize: '12px',
                        boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)',
                      }}
                    />
                    <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                      {severityChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Historical Trend */}
            <div className="cyber-card p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-sky-400" />
                    Vulnerability Findings Trend
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Historical vulnerability distribution across audit executions.
                  </p>
                </div>
              </div>

              <div className="h-64 w-full flex items-center justify-center" style={{ minHeight: '260px' }}>
                {data?.historical_trends && data.historical_trends.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260} minWidth={100}>
                    <LineChart data={data.historical_trends} margin={{ top: 15, right: 15, left: -20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '12px',
                          color: '#f8fafc',
                          fontSize: '12px',
                          boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)',
                        }}
                      />
                      <Line
                        type="monotone"
                        dataKey="total"
                        stroke="#0ea5e9"
                        strokeWidth={2.5}
                        dot={{ fill: '#0ea5e9', r: 4, strokeWidth: 2, stroke: '#030712' }}
                        activeDot={{ r: 6, fill: '#38bdf8' }}
                        name="Total Findings"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-xs text-slate-500 font-medium">
                    Run additional scans to populate historical trend analysis.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Common Misconfigurations and Recent Scans */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Common Misconfigurations */}
            <div className="cyber-card p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold text-white">Most Prevalent Misconfigurations</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Highest-frequency security weaknesses across your assessments.
                  </p>
                </div>
                <Link
                  to="/findings"
                  className="text-xs text-sky-400 hover:text-sky-300 font-semibold flex items-center gap-1 transition-colors"
                >
                  <span>View All</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>

              <div className="space-y-2.5">
                {data?.common_misconfigurations && data.common_misconfigurations.length > 0 ? (
                  data.common_misconfigurations.map((item, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3.5 rounded-xl border border-slate-800/80 bg-slate-950/60 hover:border-slate-700/80 hover:bg-slate-900/40 transition-all duration-150"
                    >
                      <div className="min-w-0 pr-3">
                        <div className="text-xs font-semibold text-slate-200 truncate">{item.title}</div>
                        <div className="text-[11px] text-slate-500 capitalize mt-0.5 font-mono">
                          Category: {item.category}
                        </div>
                      </div>
                      <div className="flex items-center gap-2.5 flex-shrink-0">
                        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-slate-800/80 text-sky-400 border border-slate-700/50">
                          {item.count}x
                        </span>
                        <SeverityBadge severity={item.severity} size="sm" />
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 py-6 text-center">No findings recorded yet.</p>
                )}
              </div>
            </div>

            {/* Recent Scans */}
            <div className="cyber-card p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold text-white">Recent Audit Activity</h3>
                  <p className="text-xs text-slate-400 mt-0.5">Latest web security scan evaluations.</p>
                </div>
                <Link
                  to="/scans"
                  className="text-xs text-sky-400 hover:text-sky-300 font-semibold flex items-center gap-1 transition-colors"
                >
                  <span>Full History</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>

              <div className="space-y-2.5">
                {data?.recent_scans && data.recent_scans.length > 0 ? (
                  data.recent_scans.map((scan) => (
                    <Link
                      key={scan.id}
                      to={`/scans/${scan.id}`}
                      className="block p-3.5 rounded-xl border border-slate-800/80 bg-slate-950/60 hover:border-sky-500/40 hover:bg-slate-900/40 transition-all duration-150 group"
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-bold text-sky-400 group-hover:text-sky-300 flex items-center gap-1.5 truncate font-mono max-w-[260px]">
                          <Globe className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                          {scan.target_hostname}
                          <ExternalLink className="w-3 h-3 text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </span>
                        <StatusBadge status={scan.status} size="sm" />
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                        <span>{new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • {new Date(scan.created_at).toLocaleDateString()}</span>
                        <span className="text-amber-400 font-medium">
                          {scan.total_findings} findings
                        </span>
                      </div>
                    </Link>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 py-6 text-center">No scans recorded yet.</p>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
