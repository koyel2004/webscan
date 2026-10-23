import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  History,
  Search,
  ExternalLink,
  Trash2,
  FileDown,
  FileCode,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Filter,
} from 'lucide-react';
import { api } from '../services/api';
import { Scan, ScanStatus } from '../types';
import { StatusBadge } from '../components/common/StatusBadge';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';

export const ScanHistoryPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const res = await api.getScans({
        page,
        limit: 10,
        hostname: search || undefined,
        status: statusFilter === 'ALL' ? undefined : (statusFilter as ScanStatus),
      });
      setScans(res.items);
      setTotalPages(res.total_pages);
      setTotal(res.total);
    } catch (err: any) {
      console.error('Error fetching scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [page, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchScans();
  };

  const handleDelete = async (scanId: string) => {
    try {
      setDeletingId(scanId);
      await api.deleteScan(scanId);
      setDeleteConfirmId(null);
      await fetchScans();
    } catch (err: any) {
      alert('Failed to delete scan: ' + (err?.response?.data?.detail || err?.message));
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <History className="w-6 h-6 text-sky-400" />
            Security Assessment History
          </h1>
          <p className="text-sm text-slate-400">
            Audit logs and vulnerability reports from previous website assessments ({total} total).
          </p>
        </div>

        <Link
          to="/scans/new"
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 transition-colors shadow-sm shadow-sky-500/25 self-start sm:self-auto"
        >
          New Assessment
        </Link>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 p-4 rounded-xl border border-slate-800 bg-slate-900/50">
        <form onSubmit={handleSearchSubmit} className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Search by target hostname (e.g. example.com)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 placeholder-slate-400 text-xs focus:border-sky-500 outline-none"
          />
        </form>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400 flex-shrink-0" />
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter scans by status"
            className="px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-xs focus:border-sky-500 outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPLETED">Completed</option>
            <option value="RUNNING">Running</option>
            <option value="PENDING">Pending</option>
            <option value="FAILED">Failed</option>
            <option value="CANCELLED">Cancelled</option>
          </select>
        </div>
      </div>

      {/* Scans Table */}
      {loading ? (
        <LoadingSpinner label="Loading scan history..." />
      ) : scans.length === 0 ? (
        <EmptyState
          title="No Scans Found"
          description={search ? `No scan records matched "${search}".` : "You haven't run any security scans yet."}
          actionText={search ? 'Clear Search' : 'Run New Scan'}
          onAction={() => {
            if (search) {
              setSearch('');
              fetchScans();
            } else {
              window.location.href = '/scans/new';
            }
          }}
        />
      ) : (
        <div className="cyber-card overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Target Hostname</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Findings Breakdown</th>
                  <th className="py-3 px-4">Duration</th>
                  <th className="py-3 px-4">Executed At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="font-medium text-slate-100 hover:text-sky-400 flex items-center gap-1.5"
                      >
                        <span className="truncate max-w-[200px] sm:max-w-xs">{scan.target_hostname}</span>
                        <ExternalLink className="w-3 h-3 text-slate-400 flex-shrink-0" />
                      </Link>
                      <span className="block text-[11px] font-mono text-slate-400">
                        IP: {scan.target_ip || 'N/A'}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <StatusBadge status={scan.status} size="sm" />
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {scan.critical_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-950/60 text-red-400 border border-red-500/30">
                            {scan.critical_count} Crit
                          </span>
                        )}
                        {scan.high_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-orange-950/60 text-orange-400 border border-orange-500/30">
                            {scan.high_count} High
                          </span>
                        )}
                        {scan.medium_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950/60 text-amber-400 border border-amber-500/30">
                            {scan.medium_count} Med
                          </span>
                        )}
                        {scan.low_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-950/60 text-blue-400 border border-blue-500/30">
                            {scan.low_count} Low
                          </span>
                        )}
                        {scan.total_findings === 0 && (
                          <span className="text-[11px] text-emerald-400 font-medium">0 Findings</span>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {scan.duration_seconds ? `${scan.duration_seconds}s` : '—'}
                    </td>

                    <td className="py-3.5 px-4 text-slate-400">
                      {new Date(scan.created_at).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
                        >
                          Details
                        </Link>

                        <a
                          href={api.getReportPdfUrl(scan.id)}
                          download
                          title="Download PDF Report"
                          className="p-1 rounded text-slate-400 hover:text-sky-400 hover:bg-slate-800 transition-colors"
                        >
                          <FileDown className="w-4 h-4" />
                        </a>

                        <a
                          href={api.getReportJsonUrl(scan.id)}
                          download
                          title="Export JSON Report"
                          className="p-1 rounded text-slate-400 hover:text-emerald-400 hover:bg-slate-800 transition-colors"
                        >
                          <FileCode className="w-4 h-4" />
                        </a>

                        {deleteConfirmId === scan.id ? (
                          <div className="inline-flex items-center gap-1 bg-red-950/60 p-1 rounded border border-red-500/40">
                            <span className="text-[10px] text-red-300">Confirm?</span>
                            <button
                              onClick={() => handleDelete(scan.id)}
                              disabled={deletingId === scan.id}
                              className="px-1.5 py-0.5 rounded bg-red-600 text-[10px] text-white hover:bg-red-500 font-bold"
                            >
                              Yes
                            </button>
                            <button
                              onClick={() => setDeleteConfirmId(null)}
                              className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 hover:bg-slate-700"
                            >
                              No
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setDeleteConfirmId(scan.id)}
                            title="Delete Record"
                            className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 bg-slate-950/40">
              <span className="text-xs text-slate-400">
                Page {page} of {totalPages} ({total} scans)
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
        </div>
      )}
    </div>
  );
};
