import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { CheckCircle, XCircle } from "lucide-react";
import { healthCheck, type HealthCheck } from "../api/client";
import { modules } from "../lib/modules";
import { getHistory, type HistoryEntry } from "../lib/history";

function timeAgo(at: number, t: TFunction): string {
  const s = Math.floor((Date.now() - at) / 1000);
  if (s < 60) return t("dashboard.justNow");
  const m = Math.floor(s / 60);
  if (m < 60) return t("dashboard.minutesAgo", { n: m });
  const h = Math.floor(m / 60);
  if (h < 24) return t("dashboard.hoursAgo", { n: h });
  return t("dashboard.daysAgo", { n: Math.floor(h / 24) });
}

export default function Dashboard() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [error, setError] = useState(false);
  const [history, setHistory] = useState<HistoryEntry[]>(() => getHistory());

  useEffect(() => {
    const refresh = () => setHistory(getHistory());
    window.addEventListener("sectk:history-updated", refresh);
    return () => window.removeEventListener("sectk:history-updated", refresh);
  }, []);

  useEffect(() => {
    healthCheck()
      .then(setHealth)
      .catch(() => setError(true));
  }, []);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">
          {t("dashboard.title")}
        </h1>
        <p className="text-muted mt-2">{t("dashboard.subtitle")}</p>
      </div>

      {/* Health Status */}
      <div className="bg-card rounded-xl border border-border p-6 mb-8">
        <h2 className="text-lg font-semibold mb-4 text-foreground">
          {t("dashboard.systemStatus")}
        </h2>
        {error ? (
          <div className="flex items-center gap-2 text-red-400">
            <XCircle className="w-5 h-5" />
            <span>{t("dashboard.backendDown")}</span>
          </div>
        ) : health ? (
          <div>
            <div className="flex items-center gap-2 text-green-400 mb-4">
              <CheckCircle className="w-5 h-5" />
              <span>
                {t("dashboard.backendOnline", { version: health.version })}
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {["virustotal", "abuseipdb", "shodan", "urlscan", "otx"].map(
                (api) => (
                  <span
                    key={api}
                    className={`px-3 py-1 rounded-full text-xs font-medium border ${
                      health.configured_apis.includes(api)
                        ? "bg-green-500/10 text-green-400 border-green-500/30"
                        : "bg-foreground/5 text-muted border-border"
                    }`}
                  >
                    {api}
                  </span>
                ),
              )}
            </div>
          </div>
        ) : (
          <p className="text-muted">{t("dashboard.checking")}</p>
        )}
      </div>

      {history.length > 0 && (
        <div className="mb-8">
          <h2 className="text-sm uppercase tracking-wide text-muted mb-3">
            {t("dashboard.recentActivity")}
          </h2>
          <div className="bg-card border border-border rounded-xl divide-y divide-border overflow-hidden">
            {history.slice(0, 8).map((entry, i) => {
              const mod = modules.find((m) => m.path === `/${entry.action}`);
              const Icon = mod?.icon;
              return (
                <Link
                  key={i}
                  to={mod?.path ?? "/"}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-foreground/5 transition-colors"
                >
                  {Icon && (
                    <Icon className={`w-4 h-4 shrink-0 ${mod?.color ?? ""}`} />
                  )}
                  <span className="text-sm text-foreground flex-1 truncate">
                    {mod ? t(`nav.${mod.path}`, mod.label) : entry.action}
                  </span>
                  <span className="text-xs text-muted shrink-0">
                    {entry.findings > 0
                      ? t("dashboard.findings", { n: entry.findings }) + " · "
                      : ""}
                    {timeAgo(entry.at, t)}
                  </span>
                </Link>
              );
            })}
          </div>
        </div>
      )}

      {/* Module Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {modules.map(({ path, label, description, icon: Icon, color, tint }) => (
          <Link
            key={path}
            to={path}
            className="bg-card rounded-xl border border-border p-6 hover:border-foreground/20 transition-colors group"
          >
            <div
              className={`w-12 h-12 rounded-lg ${tint} flex items-center justify-center mb-4`}
            >
              <Icon className={`w-6 h-6 ${color}`} />
            </div>
            <h3 className="text-lg font-semibold text-foreground">
              {t(`nav.${path}`, label)}
            </h3>
            <p className="text-sm text-muted mt-2">{description}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
