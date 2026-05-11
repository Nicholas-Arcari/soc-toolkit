import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Crosshair, Shield, Activity, AlertCircle } from "lucide-react";
import { healthCheck, listTargets, type HealthCheck, type Target } from "../api/client";

export default function Dashboard() {
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([healthCheck(), listTargets()])
      .then(([h, t]) => {
        if (cancelled) return;
        setHealth(h);
        setTargets(t);
      })
      .catch((e) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="max-w-5xl space-y-6">
      <header>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Crosshair className="w-8 h-8 text-primary-500" />
          OSINT Toolkit
        </h1>
        <p className="text-gray-400 mt-2">
          Attack surface management and investigative OSINT - passive by default.
        </p>
      </header>

      {error && (
        <div className="bg-red-950/50 border border-red-900/50 rounded-lg p-4 flex items-center gap-3 text-red-300">
          <AlertCircle className="w-5 h-5" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          icon={<Activity className="w-5 h-5 text-primary-400" />}
          label="Backend"
          value={health ? health.status : "…"}
          hint={health ? `v${health.version}` : ""}
        />
        <StatCard
          icon={<Crosshair className="w-5 h-5 text-primary-400" />}
          label="Active targets"
          value={String(targets.length)}
          hint={targets.length === 0 ? "Create one to start" : "See Targets"}
        />
        <StatCard
          icon={<Shield className="w-5 h-5 text-primary-400" />}
          label="Active scanning"
          value={health?.active_scanning_enabled ? "Enabled" : "Disabled"}
          hint={health?.active_scanning_enabled ? "opt-in flag set" : "passive only"}
        />
      </div>

      <div className="bg-dark-card border border-dark-border rounded-lg p-6 space-y-3">
        <h2 className="text-lg font-semibold">Configured external APIs</h2>
        {health && health.configured_apis.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {health.configured_apis.map((name) => (
              <span
                key={name}
                className="px-3 py-1 rounded-full bg-primary-600/20 text-primary-300 text-xs font-medium"
              >
                {name}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400">
            No API keys configured. The toolkit runs in degraded mode - crt.sh
            (no key, passive) still works; SecurityTrails / Shodan sections
            stay empty.
          </p>
        )}
      </div>

      <div className="bg-dark-card border border-dark-border rounded-lg p-6 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Recent targets</h2>
          <Link
            to="/targets"
            className="text-sm text-primary-400 hover:text-primary-300"
          >
            Manage →
          </Link>
        </div>
        {targets.length === 0 ? (
          <p className="text-sm text-gray-400">No targets yet.</p>
        ) : (
          <ul className="divide-y divide-dark-border">
            {targets.slice(0, 5).map((t) => (
              <li key={t.id} className="py-2 flex justify-between">
                <Link
                  to={`/targets/${t.id}`}
                  className="text-sm text-white hover:text-primary-300"
                >
                  {t.name}
                </Link>
                <span className="text-xs text-gray-500">
                  {t.scope_domains.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-lg p-4">
      <div className="flex items-center gap-2 text-xs text-gray-400">
        {icon}
        {label}
      </div>
      <div className="text-2xl font-bold mt-1">{value}</div>
      <div className="text-xs text-gray-500 mt-1">{hint}</div>
    </div>
  );
}
