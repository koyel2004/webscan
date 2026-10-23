import React, { useEffect, useState } from 'react';
import {
  BookOpen,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Layers,
  FileCheck2,
  CheckCircle,
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityMethodology } from '../types';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const MethodologyPage: React.FC = () => {
  const [methodology, setMethodology] = useState<SecurityMethodology | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMethodology = async () => {
      try {
        setLoading(true);
        const data = await api.getMethodology();
        setMethodology(data);
      } catch (err: any) {
        console.error('Error fetching methodology:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchMethodology();
  }, []);

  if (loading) {
    return <LoadingSpinner label="Loading security audit methodology..." />;
  }

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <BookOpen className="w-6 h-6 text-sky-400" />
          Security Assessment Methodology & Audit Principles
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Detailed documentation of defensive check specifications, classification standards, and operational boundaries.
        </p>
      </div>

      {/* Operational Boundaries */}
      <div className="p-6 rounded-xl border border-sky-500/20 bg-sky-950/10 space-y-4">
        <h2 className="text-base font-bold text-sky-300 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-sky-400" />
          Defensive & Non-Destructive Principles
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60">
            <div className="font-semibold text-slate-200 mb-1">Non-Destructive Scanning</div>
            <p className="text-slate-400 leading-relaxed">
              Probes consist exclusively of benign HTTP GET/HEAD requests and standard TLS socket handshakes.
              No password bruteforcing, SQL injection, fuzzing, or exploit payloads are executed.
            </p>
          </div>

          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60">
            <div className="font-semibold text-slate-200 mb-1">SSRF & Target Defense</div>
            <p className="text-slate-400 leading-relaxed">
              Every target domain is resolved and checked against RFC 1918 private subnets, loopback ranges,
              link-local addresses, and cloud instance metadata (169.254.169.254) to eliminate SSRF abuse.
            </p>
          </div>

          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60">
            <div className="font-semibold text-slate-200 mb-1">Strict Credential Redaction</div>
            <p className="text-slate-400 leading-relaxed">
              Raw cookie values and authorization headers observed during response inspection are immediately
              redacted from memory and never stored in SQLite or written into assessment reports.
            </p>
          </div>

          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60">
            <div className="font-semibold text-slate-200 mb-1">Audit Limitations</div>
            <p className="text-slate-400 leading-relaxed">
              External configuration assessments evaluate visible perimeter posture. They are not a substitute
              for manual penetration tests, authenticated role audits, or source code static analysis.
            </p>
          </div>
        </div>
      </div>

      {/* Check Inventory */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Layers className="w-5 h-5 text-sky-400" />
          Modular Inspection Check Specifications
        </h2>

        <div className="space-y-3">
          {methodology?.checks.map((check) => (
            <div
              key={check.check_id}
              className="cyber-card p-5 flex flex-col sm:flex-row sm:items-start justify-between gap-3"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm text-slate-100">{check.name}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-400">
                    {check.category}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{check.description}</p>
              </div>

              <div className="flex-shrink-0">
                <span className="text-[11px] font-mono text-sky-400/80 bg-sky-950/40 px-2 py-1 rounded border border-sky-500/20">
                  {check.check_id}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Severity Scoring Model */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          Severity Classification & Remediation SLAs
        </h2>

        <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Classification Criteria</th>
                <th className="py-3 px-4">Remediation SLA</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {methodology?.severity_model.map((rule) => (
                <tr key={rule.severity} className="hover:bg-slate-800/30">
                  <td className="py-3 px-4 font-bold">
                    <span
                      className={
                        rule.severity === 'CRITICAL'
                          ? 'text-red-400'
                          : rule.severity === 'HIGH'
                          ? 'text-orange-400'
                          : rule.severity === 'MEDIUM'
                          ? 'text-amber-400'
                          : rule.severity === 'LOW'
                          ? 'text-blue-400'
                          : 'text-slate-400'
                      }
                    >
                      {rule.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-300 max-w-md">{rule.criteria}</td>
                  <td className="py-3 px-4 font-medium text-slate-400">{rule.sla}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
