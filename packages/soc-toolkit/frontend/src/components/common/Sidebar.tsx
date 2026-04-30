import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  LogOut,
  Mail,
  FileText,
  Search,
  GitBranch,
  FileSearch,
  Radar,
  Share2,
  Shield,
} from "lucide-react";
import { useOptionalAuth } from "@sec-toolkit/common/auth";

const navItems = [
  { path: "/", label: "Dashboard", icon: LayoutDashboard },
  { path: "/phishing", label: "Phishing Analyzer", icon: Mail },
  { path: "/logs", label: "Log Analyzer", icon: FileText },
  { path: "/ioc", label: "IOC Extractor", icon: Search },
  { path: "/ioc-pivot", label: "IOC Pivot", icon: GitBranch },
  { path: "/yara", label: "YARA Scanner", icon: FileSearch },
  { path: "/sigma", label: "Sigma Detection", icon: Radar },
  { path: "/misp", label: "MISP Enrichment", icon: Share2 },
];

export default function Sidebar() {
  const auth = useOptionalAuth();
  const state = auth?.state ?? null;
  const logout = auth?.logout;

  return (
    <aside className="w-64 bg-dark-card border-r border-dark-border flex flex-col">
      <div className="p-6 border-b border-dark-border">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-primary-500" />
          <div>
            <h1 className="text-lg font-bold">SOC Toolkit</h1>
            <p className="text-xs text-gray-400">v0.1.0</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map(({ path, label, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            end={path === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive
                  ? "bg-primary-600/20 text-primary-400"
                  : "text-gray-400 hover:bg-dark-border/50 hover:text-white"
              }`
            }
          >
            <Icon className="w-5 h-5" />
            <span className="text-sm font-medium">{label}</span>
          </NavLink>
        ))}
      </nav>

      {state && logout && (
        <div className="p-4 border-t border-dark-border space-y-2">
          <div className="px-1 text-xs text-gray-400 truncate" title={state.user.username}>
            Signed in as <span className="text-gray-200">{state.user.username}</span>
          </div>
          <button
            type="button"
            onClick={logout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-gray-400 hover:bg-dark-border/50 hover:text-white text-sm"
          >
            <LogOut className="w-4 h-4" />
            Sign out
          </button>
        </div>
      )}

      <div className="p-4 border-t border-dark-border">
        <p className="text-xs text-gray-500 text-center">
          Nicholas Arcari
        </p>
      </div>
    </aside>
  );
}
