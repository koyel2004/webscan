import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  FileText,
  FileDown,
  FileCode,
  ExternalLink,
  ShieldCheck,
  Calendar,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import { Scan } from '../types';
import { StatusBadge } from '../components/common/StatusBadge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';

export const ReportsPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        const res = await api.getScans({ page: 1, limit: 20 });
        setScans(res.items);
      } catch (err: any) {
        console.error('Error fetching reports:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchReports();
  }, []);

  const getExecutiveGrade = (scan: Scan) => {
    if (scan.critical_count > 0) return { grade: 'F', color: 'text-red-400 bg-red-950/40 border-red-500/40' };
    if (scan.high_count > 2) return { grade: 'D', color: 'text-orange-400 bg-orange-950/40 border-orange-500/40' };
    if (scan.high_count > 0 || scan.medium_count > 3) return { grade: 'C', color: 'text-amber-400 bg-amber-950/40 border-amber-500/40' };
    if (scan.medium_count > 0 || scan.low_count > 2) return { grade: 'B', color: 'text-blue-400 bg-blue-950/40 border-blue-500/40' };
    return { grade: 'A', color: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/40' };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <FileText className="w-6 h-6 text-sky-400" />
          Security Audit Reports
        </h1>
        <p className="text-sm text-slate-400">
          Executive security reports ready for PDF generation and JSON schema exports.
        </p>
      </div>

      {loading ? (
        <LoadingSpinner label="Loading assessment reports..." />
      ) : scans.length === 0 ? (
        <EmptyState
          title="No Reports Generated Yet"
          description="Complete your first security assessment to generate executive PDF and JSON reports."
          actionText="Run New Scan"
          onAction={() => (window.location.href = '/scans/new')}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scans.map((scan) => {
            const gradeInfo = getExecutiveGrade(scan);
            return (
              <div
                key={scan.id}
                className="cyber-card p-6 flex flex-col justify-between space-y-4"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div>
                      <div className="text-xs uppercase font-mono tracking-wider text-sky-400 font-semibold">
                        Assessment Report
                      </div>
                      <h2 className="text-base font-bold text-white truncate max-w-xs sm:max-w-sm mt-0.5">
                        {scan.target_hostname}
                      </h2>
                    </div>

                    <div
                      className={`flex items-center justify-center w-9 h-9 rounded-lg border font-bold text-base ${gradeInfo.color}`}
                      title={`Security Grade: ${gradeInfo.grade}`}
                    >
                      {gradeInfo.grade}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800/80">
                    <div className="flex items-center gap-1.5">
                      <Calendar className="w-3.5 h-3.5 text-slate-400" />
                      <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-slate-400" />
                      <span>{scan.total_findings} findings</span>
                    </div>
                  </div>

                  <div className="mt-2 text-xs font-mono text-slate-400 truncate">
                    Target: {scan.target_url}
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                  <Link
                    to={`/scans/${scan.id}`}
                    className="text-xs font-medium text-slate-300 hover:text-sky-400 flex items-center gap-1"
                  >
                    View Breakdown <ExternalLink className="w-3 h-3" />
                  </Link>

                  <div className="flex items-center gap-2">
                    <a
                      href={api.getReportPdfUrl(scan.id)}
                      download
                      className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white transition-colors"
                    >
                      <FileDown className="w-3.5 h-3.5" />
                      <span>PDF</span>
                    </a>

                    <a
                      href={api.getReportJsonUrl(scan.id)}
                      download
                      className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
                    >
                      <FileCode className="w-3.5 h-3.5" />
                      <span>JSON</span>
                    </a>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
