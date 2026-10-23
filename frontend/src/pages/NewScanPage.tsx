import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  ShieldAlert,
  Play,
  Ban,
  CheckCircle2,
  AlertCircle,
  ShieldCheck,
  Info,
} from 'lucide-react';
import { api } from '../services/api';
import { Scan } from '../types';
import { StatusBadge } from '../components/common/StatusBadge';

const scanSchema = z.object({
  target_url: z
    .string()
    .min(1, 'Target URL is required.')
    .refine(
      (val) => {
        try {
          const testUrl = val.startsWith('http://') || val.startsWith('https://') ? val : `https://${val}`;
          const parsed = new URL(testUrl);
          return parsed.hostname.length > 0 && parsed.hostname.includes('.');
        } catch {
          return false;
        }
      },
      {
        message: 'Please enter a valid website URL or domain name (e.g. https://example.com).',
      }
    ),
  user_authorized: z.boolean().refine((val) => val === true, {
    message: 'You must confirm explicit authorization to perform security assessment on this target.',
  }),
  profile: z.string().default('safe_default'),
  timeout_seconds: z.coerce.number().min(1).max(30).default(10),
});

type ScanFormData = {
  target_url: string;
  user_authorized: boolean;
  profile: string;
  timeout_seconds: number;
};

export const NewScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ScanFormData>({
    resolver: zodResolver(scanSchema) as any,
    defaultValues: {
      target_url: '',
      user_authorized: false,
      profile: 'safe_default',
      timeout_seconds: 10,
    },
  });

  // Polling active scan status until finished
  useEffect(() => {
    let intervalId: any = null;

    if (activeScan && (activeScan.status === 'PENDING' || activeScan.status === 'RUNNING')) {
      intervalId = setInterval(async () => {
        try {
          const updated = await api.getScan(activeScan.id);
          setActiveScan(updated);
        } catch (err: any) {
          setPollError(err?.message || 'Error tracking scan status.');
        }
      }, 1500);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [activeScan?.id, activeScan?.status]);

  const onSubmit = async (data: ScanFormData) => {
    try {
      setIsSubmitting(true);
      setPollError(null);
      const scan = await api.createScan({
        target_url: data.target_url,
        user_authorized: data.user_authorized,
        profile: data.profile,
        timeout_seconds: data.timeout_seconds,
      });
      setActiveScan(scan);
    } catch (err: any) {
      setPollError(err?.response?.data?.message || err?.message || 'Failed to initialize scan.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = async () => {
    if (!activeScan) return;
    try {
      const cancelled = await api.cancelScan(activeScan.id);
      setActiveScan(cancelled);
    } catch (err: any) {
      alert('Could not cancel scan: ' + (err?.response?.data?.detail || err?.message));
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-sky-400" />
          Launch Security Assessment
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Perform controlled, non-destructive security auditing on target web applications.
        </p>
      </div>

      {/* Active Scan Progress Card */}
      {activeScan && (
        <div className="p-6 rounded-xl border border-sky-500/30 bg-sky-950/20 backdrop-blur-md shadow-lg shadow-sky-500/5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-sky-900/40">
            <div>
              <div className="text-xs uppercase tracking-wider font-mono text-sky-400 font-semibold">
                Scan in Progress
              </div>
              <div className="text-lg font-bold text-white flex items-center gap-2 mt-0.5">
                <span>{activeScan.target_hostname}</span>
                <span className="text-xs font-mono text-slate-400 font-normal">
                  ({activeScan.target_ip || 'Resolving IP...'})
                </span>
              </div>
            </div>
            <div>
              <StatusBadge status={activeScan.status} />
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div>
              <span className="text-slate-400 block">Scan ID:</span>
              <span className="font-mono text-slate-200">{activeScan.id.slice(0, 12)}...</span>
            </div>
            <div>
              <span className="text-slate-400 block">Profile:</span>
              <span className="text-slate-200 capitalize">{activeScan.profile}</span>
            </div>
            <div>
              <span className="text-slate-400 block">Duration:</span>
              <span className="text-slate-200 font-mono">
                {activeScan.duration_seconds ? `${activeScan.duration_seconds}s` : 'Probing...'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block">Findings Found:</span>
              <span className="text-amber-400 font-bold">{activeScan.total_findings}</span>
            </div>
          </div>

          {activeScan.status === 'RUNNING' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-sky-300">
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
                  Executing security inspection checks (Headers, Cookies, CORS, TLS)...
                </span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-sky-500 h-full w-2/3 animate-pulse rounded-full" />
              </div>
            </div>
          )}

          {activeScan.status === 'COMPLETED' && (
            <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/30 flex items-center justify-between">
              <div className="flex items-center gap-3 text-emerald-300 text-sm">
                <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
                <span>Assessment complete! <b>{activeScan.total_findings}</b> security observations recorded.</span>
              </div>
              <button
                onClick={() => navigate(`/scans/${activeScan.id}`)}
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
              >
                View Full Audit Report &rarr;
              </button>
            </div>
          )}

          {activeScan.status === 'FAILED' && (
            <div className="p-4 rounded-lg bg-red-950/30 border border-red-500/30 text-red-300 text-xs">
              <div className="font-semibold mb-1">Scan Terminated with Error:</div>
              <p>{activeScan.error_message || 'Unexpected failure during target probing.'}</p>
            </div>
          )}

          {(activeScan.status === 'RUNNING' || activeScan.status === 'PENDING') && (
            <div className="flex justify-end pt-2">
              <button
                onClick={handleCancel}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-800/80 bg-red-950/40 hover:bg-red-900/60 text-red-400 transition-colors"
              >
                <Ban className="w-3.5 h-3.5" />
                Cancel Assessment
              </button>
            </div>
          )}
        </div>
      )}

      {/* Target Setup Form */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2">
          <form
            onSubmit={handleSubmit(onSubmit)}
            className="cyber-card p-6 md:p-8 space-y-6"
          >
            {/* Target URL */}
            <div className="space-y-2">
              <label htmlFor="target_url" className="block text-sm font-semibold text-slate-200">
                Target Website URL or Domain <span className="text-red-400">*</span>
              </label>
              <div className="relative">
                <input
                  id="target_url"
                  type="text"
                  placeholder="https://example.com"
                  {...register('target_url')}
                  disabled={isSubmitting || (activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING')}
                  className="w-full px-4 py-2.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 placeholder-slate-500 text-sm focus:border-sky-500 focus:ring-1 focus:ring-sky-500 outline-none transition-colors"
                />
              </div>
              {errors.target_url && (
                <p className="text-xs text-red-400 flex items-center gap-1 mt-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.target_url.message}
                </p>
              )}
              <p className="text-[11px] text-slate-400">
                Scheme is optional (defaults to HTTPS). Private IP ranges and loopback domains are strictly blocked.
              </p>
            </div>

            {/* Scan Profile & Timeout Controls */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label htmlFor="profile" className="block text-xs font-semibold text-slate-300">
                  Scan Profile
                </label>
                <select
                  id="profile"
                  {...register('profile')}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-xs focus:border-sky-500 outline-none"
                >
                  <option value="safe_default">Safe Default (Recommended)</option>
                  <option value="passive_strict">Passive Strict (Read-Only)</option>
                </select>
              </div>

              <div className="space-y-2">
                <label htmlFor="timeout" className="block text-xs font-semibold text-slate-300">
                  Per-Request Timeout
                </label>
                <select
                  id="timeout"
                  {...register('timeout_seconds')}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-xs focus:border-sky-500 outline-none"
                >
                  <option value="5">5 Seconds (Fast)</option>
                  <option value="10">10 Seconds (Standard)</option>
                  <option value="15">15 Seconds (High Latency)</option>
                  <option value="30">30 Seconds (Max Bound)</option>
                </select>
              </div>
            </div>

            {/* Authorization Confirmation Checkbox */}
            <div className="p-4 rounded-lg border border-amber-500/20 bg-amber-950/10 space-y-2">
              <div className="flex items-start gap-3">
                <input
                  id="user_authorized"
                  type="checkbox"
                  {...register('user_authorized')}
                  className="mt-1 h-4 w-4 rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900"
                />
                <label htmlFor="user_authorized" className="text-xs text-slate-300 leading-relaxed cursor-pointer">
                  <b>Explicit Authorization Confirmation:</b> I confirm that I am authorized to perform defensive
                  security auditing on this target web asset. I understand that SentinelScan only conducts safe,
                  non-destructive checks.
                </label>
              </div>
              {errors.user_authorized && (
                <p className="text-xs text-red-400 pl-7">{errors.user_authorized.message}</p>
              )}
            </div>

            {/* Global Error Banner */}
            {pollError && (
              <div className="p-3 rounded-lg border border-red-500/30 bg-red-950/20 text-red-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{pollError}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting || (activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING')}
              className="w-full inline-flex items-center justify-center gap-2 px-6 py-3.5 text-sm font-bold rounded-xl bg-gradient-to-r from-sky-500 to-cyan-500 hover:from-sky-400 hover:to-cyan-400 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-slate-950 transition-all shadow-md shadow-sky-500/25 hover:shadow-sky-500/40 hover:-translate-y-0.5"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{isSubmitting ? 'Validating Target & Resolving DNS...' : 'Start Security Assessment'}</span>
            </button>
          </form>
        </div>

        {/* Sidebar Information / Scope */}
        <div className="space-y-4">
          <div className="cyber-card p-6 space-y-4">
            <div className="flex items-center gap-2 text-sky-400 font-bold text-sm">
              <ShieldCheck className="w-5 h-5" />
              <span>Assessment Scope</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every audit performs seven isolated defensive configuration checks:
            </p>
            <ul className="text-xs text-slate-300 space-y-2">
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                HTTPS Reachability & Redirect Enforcement
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                HTTP Security Headers (CSP, HSTS, XFO)
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                Cookie Security (Secure, HttpOnly, SameSite)
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                Cross-Origin Resource Sharing (CORS)
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                TLS Certificate Validity & Chain
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                Public Server Banner Disclosure
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                Response Hygiene & Debug Leakage
              </li>
            </ul>
          </div>

          <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/30 space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
              <Info className="w-3.5 h-3.5 text-sky-400" />
              <span>Defensive Guarantee</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              SentinelScan never attempts password bruteforcing, SQL injection, port scanning, or intrusive payloads.
              Raw cookie values are never logged or stored.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
