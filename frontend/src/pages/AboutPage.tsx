import React from 'react';
import { Info, Shield, Code2, Server, Lock } from 'lucide-react';

export const AboutPage: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="pb-4 border-b border-slate-800/80">
        <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
          <Info className="w-6 h-6 text-sky-400" />
          About SentinelScan
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Defensive Web Security Assessment and Vulnerability Analysis Platform.
        </p>
      </div>

      {/* Mission Banner */}
      <div className="cyber-card p-6 md:p-8 space-y-3 border-sky-500/30 bg-gradient-to-br from-slate-900/80 to-sky-950/20">
        <div className="flex items-center gap-2 text-sky-400 font-bold text-sm">
          <Shield className="w-5 h-5" />
          <span>Platform Mission</span>
        </div>
        <p className="text-sm text-slate-200 leading-relaxed">
          <b>SentinelScan</b> empowers security engineers, software architects, and DevOps professionals to evaluate
          web assets against common security misconfigurations using safe, non-destructive, and evidence-grounded
          probes. It focuses on the defensive posture of HTTP security headers, cookies, CORS policies, HTTPS
          redirection, and TLS certificate hygiene.
        </p>
      </div>

      {/* Technology Stack Grid */}
      <div className="space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Code2 className="w-5 h-5 text-sky-400" />
          Technology Stack
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="cyber-card p-5 space-y-3">
            <div className="font-bold text-slate-100 flex items-center gap-2 text-sm">
              <Code2 className="w-4 h-4 text-sky-400" />
              <span>Frontend Architecture</span>
            </div>
            <ul className="text-slate-400 space-y-1.5 list-disc list-inside">
              <li>React 19 with Vite & TypeScript</li>
              <li>Tailwind CSS Cyber-Dark Design System</li>
              <li>React Router v7 Declarative Navigation</li>
              <li>Recharts Telemetry Data Visualizations</li>
              <li>React Hook Form & Zod Schema Validation</li>
              <li>Lucide Icons Library</li>
            </ul>
          </div>

          <div className="cyber-card p-5 space-y-3">
            <div className="font-bold text-slate-100 flex items-center gap-2 text-sm">
              <Server className="w-4 h-4 text-emerald-400" />
              <span>Backend & Scanner Engine</span>
            </div>
            <ul className="text-slate-400 space-y-1.5 list-disc list-inside">
              <li>Python 3.11+ with FastAPI & Uvicorn</li>
              <li>SQLAlchemy 2.0 ORM & Alembic Migrations</li>
              <li>HTTPX Async Controlled Transport (2MB cap)</li>
              <li>Standard-Library Python SSL Handshake</li>
              <li>ReportLab PDF Assessment Engine</li>
              <li>Structured Logging with Secret Redaction</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Responsible Use & Legal Disclaimer */}
      <div className="cyber-card p-6 space-y-3 border-amber-500/30 bg-gradient-to-br from-slate-900/80 to-amber-950/20">
        <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
          <Lock className="w-4 h-4" />
          <span>Responsible Use & Assessment Disclaimer</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          SentinelScan is designed exclusively for authorized defensive assessments, compliance auditing, and
          educational evaluation. Users are strictly required to obtain explicit authorization before scanning
          any target. SentinelScan does not perform intrusive exploitation, denial-of-service, or authentication bypass.
        </p>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          No automated tool can detect all potential vulnerabilities. Results must be verified in context with your
          application's specific business logic and risk profile.
        </p>
      </div>
    </div>
  );
};
