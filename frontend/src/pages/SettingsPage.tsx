import React, { useState, useEffect } from 'react';
import { Settings, Shield, Sliders, Database, Cpu, CheckCircle2, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

export const SettingsPage: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [seedMessage, setSeedMessage] = useState<string | null>(null);

  const fetchHealth = async () => {
    try {
      setLoading(true);
      const res = await api.getHealth();
      setHealth(res);
    } catch (err: any) {
      console.error('Health fetch failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const handleSeed = async () => {
    try {
      setSeeding(true);
      setSeedMessage(null);
      const res = await api.seedDemoData();
      setSeedMessage(res.message);
    } catch (err: any) {
      setSeedMessage('Failed to seed records: ' + (err?.message || 'Unknown error'));
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Settings className="w-6 h-6 text-sky-400" />
          Scanner Engine & Application Settings
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Operational thresholds, SSRF safety parameters, and diagnostic telemetry.
        </p>
      </div>

      <div className="space-y-6">
        {/* System Diagnostic Health */}
        <div className="cyber-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sky-400" />
              Service Status & Diagnostic Health
            </h2>
            <button
              onClick={fetchHealth}
              disabled={loading}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Ping Backend"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
              <span className="text-slate-400 block mb-1">Backend API</span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {health?.status === 'ok' ? 'Online' : 'Degraded'}
              </span>
            </div>

            <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
              <span className="text-slate-400 block mb-1">Database Engine</span>
              <span className="text-slate-200 font-semibold capitalize font-mono">
                {health?.database || 'SQLite'}
              </span>
            </div>

            <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
              <span className="text-slate-400 block mb-1">Environment</span>
              <span className="text-slate-200 font-semibold capitalize font-mono">
                {health?.environment || 'Development'}
              </span>
            </div>

            <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
              <span className="text-slate-400 block mb-1">Version</span>
              <span className="text-sky-400 font-mono font-semibold">
                v{health?.version || '1.0.0'}
              </span>
            </div>
          </div>
        </div>

        {/* Security Policy Enforcements */}
        <div className="cyber-card p-6 space-y-4">
          <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Shield className="w-4 h-4 text-sky-400" />
            Active SSRF & Protection Controls (Immutable)
          </h2>
          <p className="text-xs text-slate-400">
            For security reasons, mandatory target protection rules cannot be disabled via client settings.
          </p>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/40">
              <div>
                <span className="font-semibold text-slate-200 block">Prohibit Private & Loopback Networks</span>
                <span className="text-slate-400 text-[11px]">Blocks RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and 127.0.0.0/8.</span>
              </div>
              <span className="px-2 py-1 rounded text-[11px] font-semibold bg-emerald-950/40 border border-emerald-500/30 text-emerald-400">
                ENFORCED
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/40">
              <div>
                <span className="font-semibold text-slate-200 block">Block Cloud Metadata Endpoints</span>
                <span className="text-slate-400 text-[11px]">Blocks 169.254.169.254, metadata.google.internal, and link-local ranges.</span>
              </div>
              <span className="px-2 py-1 rounded text-[11px] font-semibold bg-emerald-950/40 border border-emerald-500/30 text-emerald-400">
                ENFORCED
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/40">
              <div>
                <span className="font-semibold text-slate-200 block">Maximum Response Body Size Limit</span>
                <span className="text-slate-400 text-[11px]">Prevents resource exhaustion by truncating HTTP responses at 2 MB.</span>
              </div>
              <span className="px-2 py-1 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                2,097,152 Bytes
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/40">
              <div>
                <span className="font-semibold text-slate-200 block">Cookie Value Redaction</span>
                <span className="text-slate-400 text-[11px]">Set-Cookie header values are never written to database or logs.</span>
              </div>
              <span className="px-2 py-1 rounded text-[11px] font-semibold bg-emerald-950/40 border border-emerald-500/30 text-emerald-400">
                ACTIVE
              </span>
            </div>
          </div>
        </div>

        {/* AI Explanation Engine Status */}
        <div className="cyber-card p-6 space-y-3">
          <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-sky-400" />
            AI Explanation Engine Configuration
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            The core security scanner operates 100% deterministically using verified OWASP and NIST remediation
            rulebooks without external AI dependencies. Optional LLM enhancement is currently{' '}
            <b className="text-slate-300">{health?.ai_engine_active ? 'Enabled' : 'Disabled (Deterministic Fallback Active)'}</b>.
          </p>
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-300">
            All explanations and remediation steps rendered across findings and reports are ground-truth verified
            and never hallucinated.
          </div>
        </div>

        {/* Development Data Management */}
        <div className="cyber-card p-6 space-y-3">
          <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Database className="w-4 h-4 text-sky-400" />
            Demonstration Data
          </h2>
          <p className="text-xs text-slate-400">
            Insert sample scans and security findings for local demonstration, UI evaluation, and report testing.
          </p>
          <div>
            <button
              onClick={handleSeed}
              disabled={seeding}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              <Database className="w-3.5 h-3.5 text-sky-400" />
              <span>{seeding ? 'Seeding Demo Records...' : 'Seed Sample Assessment Data'}</span>
            </button>
            {seedMessage && (
              <p className="text-xs text-emerald-400 mt-2 font-medium">{seedMessage}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
