import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  PlusCircle,
  History,
  ShieldAlert,
  FileText,
  BookOpen,
  Settings,
  Info,
  ShieldCheck,
} from 'lucide-react';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const navItems = [
    { label: 'Overview', to: '/', icon: LayoutDashboard },
    { label: 'New Scan', to: '/scans/new', icon: PlusCircle },
    { label: 'Scan History', to: '/scans', icon: History },
    { label: 'Findings', to: '/findings', icon: ShieldAlert },
    { label: 'Reports', to: '/reports', icon: FileText },
    { label: 'Methodology', to: '/methodology', icon: BookOpen },
    { label: 'Settings', to: '/settings', icon: Settings },
    { label: 'About', to: '/about', icon: Info },
  ];

  return (
    <>
      {/* Backdrop for mobile view */}
      {isOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/70 backdrop-blur-sm md:hidden transition-opacity"
          onClick={onClose}
        />
      )}

      <aside
        className={`fixed top-16 bottom-0 left-0 z-30 w-64 border-r border-slate-800/80 bg-slate-950/90 backdrop-blur-xl transition-transform duration-200 ease-in-out md:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex flex-col h-full py-4 px-3 justify-between">
          <nav className="space-y-1.5">
            <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Workspaces
            </div>
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={onClose}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3.5 py-2.5 text-xs font-medium rounded-lg transition-all duration-150 ${
                      isActive
                        ? 'bg-sky-500/15 text-sky-300 font-semibold border border-sky-500/30 shadow-sm shadow-sky-500/20'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>

          <div className="p-3.5 rounded-xl border border-slate-800/80 bg-slate-900/50 backdrop-blur-md">
            <div className="flex items-center gap-2 mb-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-semibold text-slate-200">Defensive Shield</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Safe, non-destructive web auditor with socket-level SSRF protection.
            </p>
          </div>
        </div>
      </aside>
    </>
  );
};
