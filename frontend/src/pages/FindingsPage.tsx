import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  X,
  FileCode,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import { Finding, SeverityLevel } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';

export const FindingsPage: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  // Detail Drawer state
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const res = await api.getFindings({
        page,
        limit: 12,
        search: search || undefined,
        severity: severityFilter === 'ALL' ? undefined : (severityFilter as SeverityLevel),
        category: categoryFilter === 'ALL' ? undefined : categoryFilter,
      });
      setFindings(res.items);
      setTotalPages(res.total_pages);
      setTotal(res.total);
    } catch (err: any) {
      console.error('Error fetching findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [page, severityFilter, categoryFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchFindings();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-sky-400" />
            Security Findings & Vulnerabilities
          </h1>
          <p className="text-sm text-slate-400">
            Cross-scan security vulnerability repository with evidence and verified remediation steps ({total} total).
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-4 gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/50">
        <form onSubmit={handleSearch} className="sm:col-span-2 relative">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Search by title, summary, or CWE ID (e.g. CWE-79)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 placeholder-slate-400 text-xs focus:border-sky-500 outline-none"
          />
        </form>

        <div>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by Severity"
            className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-xs focus:border-sky-500 outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>
        </div>

        <div>
          <select
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by Category"
            className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-xs focus:border-sky-500 outline-none"
          >
            <option value="ALL">All Categories</option>
            <option value="headers">HTTP Security Headers</option>
            <option value="cookies">Cookie Attributes</option>
            <option value="cors">CORS Policy</option>
            <option value="tls">TLS & Cryptography</option>
            <option value="info_disclosure">Information Disclosure</option>
            <option value="hygiene">Response Hygiene</option>
            <option value="redirects">HTTPS & Redirects</option>
          </select>
        </div>
      </div>

      {/* Findings Grid */}
      {loading ? (
        <LoadingSpinner label="Fetching security findings..." />
      ) : findings.length === 0 ? (
        <EmptyState
          title="No Findings Match Filter"
          description="Try broadening your search query or resetting severity and category filters."
          actionText="Reset Filters"
          onAction={() => {
            setSearch('');
            setSeverityFilter('ALL');
            setCategoryFilter('ALL');
            setPage(1);
          }}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {findings.map((f) => (
            <div
              key={f.id}
              onClick={() => setSelectedFinding(f)}
              className="cyber-card p-5 cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="text-[11px] font-mono text-slate-400 capitalize">
                    {f.category}
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-slate-100 line-clamp-2 mb-1.5">
                  {f.title}
                </h3>

                <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed mb-4">
                  {f.summary}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                <span className="font-mono truncate max-w-[150px]">{f.hostname}</span>
                <span className="text-sky-400 hover:underline font-medium">Inspect Evidence &rarr;</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 rounded-xl border border-slate-800 bg-slate-900/50">
          <span className="text-xs text-slate-400">
            Page {page} of {totalPages} ({total} findings)
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded border border-slate-700 bg-slate-900 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-1.5 rounded border border-slate-700 bg-slate-900 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Detail Modal / Drawer */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow-2xl space-y-5">
            <div className="flex items-start justify-between gap-4 pb-3 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <SeverityBadge severity={selectedFinding.severity} />
                  <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                    {selectedFinding.category}
                  </span>
                  {selectedFinding.cwe_id && (
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300">
                      {selectedFinding.cwe_id}
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-white leading-tight">
                  {selectedFinding.title}
                </h2>
                <div className="text-xs text-slate-400 mt-1 font-mono">
                  Observed Host: {selectedFinding.hostname}
                </div>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Observation
                </div>
                <p className="text-slate-300 leading-relaxed">{selectedFinding.summary}</p>
              </div>

              {selectedFinding.evidence && (
                <div>
                  <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                    Observed Evidence & Headers
                  </div>
                  <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-sky-300 overflow-x-auto whitespace-pre-wrap leading-snug">
                    {selectedFinding.evidence}
                  </pre>
                </div>
              )}

              <div>
                <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Threat & Security Impact
                </div>
                <p className="text-slate-300 leading-relaxed">{selectedFinding.impact}</p>
              </div>

              <div>
                <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Remediation & Verification
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-200 leading-relaxed whitespace-pre-wrap">
                  {selectedFinding.remediation}
                </div>
              </div>

              {selectedFinding.references && (
                <div>
                  <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                    References & Standards
                  </div>
                  <div className="space-y-1">
                    {selectedFinding.references.split('\n').filter(Boolean).map((ref, idx) => (
                      <a
                        key={idx}
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

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
