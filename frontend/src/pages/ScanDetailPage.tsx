import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ArrowLeft,
  FileDown,
  FileCode,
  Clock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { api } from '../services/api';
import { Scan, Finding } from '../types';
import { StatusBadge } from '../components/common/StatusBadge';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const ScanDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'checks'>('findings');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  useEffect(() => {
    const fetchScanDetail = async () => {
      if (!id) return;
      try {
        setLoading(true);
        const data = await api.getScan(id);
        setScan(data);
      } catch (err: any) {
        setError(err?.response?.data?.detail || err?.message || 'Failed to load scan details.');
      } finally {
        setLoading(false);
      }
    };
    fetchScanDetail();
  }, [id]);

  if (loading) {
    return <LoadingSpinner label="Retrieving assessment records..." size="lg" />;
  }

  if (error || !scan) {
    return (
      <div className="p-6 rounded-xl border border-red-500/30 bg-red-950/20 text-red-300">
        <h3 className="font-semibold text-lg mb-2">Scan Not Found</h3>
        <p className="text-sm mb-4">{error || 'Unable to locate the specified scan.'}</p>
        <Link
          to="/scans"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 text-slate-200 text-xs"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to History
        </Link>
      </div>
    );
  }

  const toggleFinding = (fId: string) => {
    setExpandedFindingId((prev) => (prev === fId ? null : fId));
  };

  return (
    <div className="space-y-6">
      {/* Back button */}
      <div>
        <Link
          to="/scans"
          className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Assessment History
        </Link>
      </div>

      {/* Hero Assessment Card */}
      <div className="cyber-card p-6 md:p-8 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-sky-400 font-semibold mb-1">
              Assessment Target
            </div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <span>{scan.target_hostname}</span>
              <a
                href={scan.target_url}
                target="_blank"
                rel="noreferrer"
                className="text-slate-400 hover:text-sky-400"
                title="Open Target in New Tab"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </h1>
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-2 font-mono">
              <span>Target URL: {scan.target_url}</span>
              <span>•</span>
              <span>IP: {scan.target_ip || 'N/A'}</span>
              <span>•</span>
              <span>ID: {scan.id.slice(0, 8)}</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <StatusBadge status={scan.status} />

            <a
              href={api.getReportPdfUrl(scan.id)}
              download
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white transition-colors"
            >
              <FileDown className="w-4 h-4" />
              Download PDF Report
            </a>

            <a
              href={api.getReportJsonUrl(scan.id)}
              download
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
            >
              <FileCode className="w-4 h-4" />
              Export JSON
            </a>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4 pt-4 text-xs">
          <div>
            <span className="text-slate-400 block mb-0.5">Duration</span>
            <span className="font-semibold text-slate-200 font-mono">
              {scan.duration_seconds ? `${scan.duration_seconds}s` : '—'}
            </span>
          </div>

          <div>
            <span className="text-slate-400 block mb-0.5">Executed Checks</span>
            <span className="font-semibold text-slate-200 font-mono">
              {scan.passed_checks}/{scan.total_checks} Passed
            </span>
          </div>

          <div>
            <span className="text-slate-400 block mb-0.5">Critical / High</span>
            <span className="font-semibold text-red-400 font-mono">
              {scan.critical_count} / {scan.high_count}
            </span>
          </div>

          <div>
            <span className="text-slate-400 block mb-0.5">Medium / Low</span>
            <span className="font-semibold text-amber-400 font-mono">
              {scan.medium_count} / {scan.low_count}
            </span>
          </div>

          <div>
            <span className="text-slate-400 block mb-0.5">Informational</span>
            <span className="font-semibold text-slate-300 font-mono">{scan.info_count}</span>
          </div>

          <div>
            <span className="text-slate-400 block mb-0.5">Audit Timestamp</span>
            <span className="text-slate-300">
              {new Date(scan.created_at).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('findings')}
          className={`pb-3 relative transition-colors ${
            activeTab === 'findings'
              ? 'text-sky-400 border-b-2 border-sky-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Security Findings ({scan.findings?.length || 0})
        </button>

        <button
          onClick={() => setActiveTab('checks')}
          className={`pb-3 relative transition-colors ${
            activeTab === 'checks'
              ? 'text-sky-400 border-b-2 border-sky-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Checks Executed ({scan.check_results?.length || 0})
        </button>
      </div>

      {/* Tab 1: Findings List */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {(!scan.findings || scan.findings.length === 0) ? (
            <div className="p-8 text-center rounded-xl border border-slate-800 bg-slate-900/40 text-slate-400 text-sm">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              No security vulnerabilities or misconfigurations detected in this scan.
            </div>
          ) : (
            scan.findings.map((f, idx) => {
              const isExpanded = expandedFindingId === f.id;
              return (
                <div
                  key={f.id}
                  className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden transition-colors"
                >
                  {/* Header Row */}
                  <div
                    onClick={() => toggleFinding(f.id)}
                    className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-850/50"
                  >
                    <div className="flex items-center gap-3 min-w-0 pr-4">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-slate-100 truncate">{f.title}</div>
                        <div className="text-xs text-slate-400 flex items-center gap-3 mt-0.5">
                          <span className="capitalize">Category: {f.category}</span>
                          {f.cwe_id && <span>• CWE: {f.cwe_id}</span>}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0 text-slate-400">
                      {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                    </div>
                  </div>

                  {/* Collapsible Details */}
                  {isExpanded && (
                    <div className="p-5 border-t border-slate-800 bg-slate-950/40 space-y-4 text-xs">
                      <div>
                        <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                          Observation Summary
                        </div>
                        <p className="text-slate-300 leading-relaxed">{f.summary}</p>
                      </div>

                      {f.evidence && (
                        <div>
                          <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                            Observed Evidence
                          </div>
                          <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-sky-300 overflow-x-auto whitespace-pre-wrap leading-snug">
                            {f.evidence}
                          </pre>
                        </div>
                      )}

                      <div>
                        <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                          Security Impact Analysis
                        </div>
                        <p className="text-slate-300 leading-relaxed">{f.impact}</p>
                      </div>

                      <div>
                        <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                          Remediation Guidance & Verification
                        </div>
                        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-200 leading-relaxed whitespace-pre-wrap">
                          {f.remediation}
                        </div>
                      </div>

                      {f.references && (
                        <div>
                          <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                            Official Standards & References
                          </div>
                          <div className="space-y-1">
                            {f.references.split('\n').filter(Boolean).map((ref, rIdx) => (
                              <a
                                key={rIdx}
                                href={ref}
                                target="_blank"
                                rel="noreferrer"
                                className="text-sky-400 hover:underline flex items-center gap-1"
                              >
                                {ref} <ExternalLink className="w-3 h-3 inline" />
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Tab 2: Check Execution Matrix */}
      {activeTab === 'checks' && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Security Check</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Outcome Status</th>
                  <th className="py-3 px-4">Execution Time</th>
                  <th className="py-3 px-4">Result Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {scan.check_results?.map((cr) => (
                  <tr key={cr.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-medium text-slate-200">{cr.check_name}</td>
                    <td className="py-3 px-4 uppercase text-slate-400">{cr.category}</td>
                    <td className="py-3 px-4">
                      <StatusBadge status={cr.status} size="sm" />
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{cr.duration_ms.toFixed(1)} ms</td>
                    <td className="py-3 px-4 text-slate-300 max-w-sm truncate" title={cr.message}>
                      {cr.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
