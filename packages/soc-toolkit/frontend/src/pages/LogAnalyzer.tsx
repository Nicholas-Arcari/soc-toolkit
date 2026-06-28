import { useState } from "react";
import { useTranslation } from "react-i18next";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { FileUpload, SeverityBadge } from "@sec-toolkit/common/components";
import { useTheme } from "@sec-toolkit/common/theme";
import { analyzeLogs, awardXp, type LogAnalysisResult } from "../api/client";

export default function LogAnalyzer() {
  const { t } = useTranslation();
  const [result, setResult] = useState<LogAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logType, setLogType] = useState("auto");
  const { theme } = useTheme();

  // Recharts paints SVG via props, not classes, so chart chrome can't use the
  // Tailwind theme tokens - pick colours from the current theme instead. These
  // mirror the CSS variables in index.css (muted / card / border / foreground).
  const chart =
    theme === "dark"
      ? { axis: "#a1a1aa", bg: "#161617", border: "#27272a", text: "#fafafa" }
      : { axis: "#52525b", bg: "#ffffff", border: "#e4e4e7", text: "#0a0a0a" };

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeLogs(file, logType);
      setResult(data);
      awardXp("logs", data.alerts.length);
    } catch {
      setError(t("logs.error"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("logs.title")}</h1>
        <p className="text-muted mt-2">{t("logs.subtitle")}</p>
      </div>

      {/* Log Type Selector */}
      <div className="mb-6 flex gap-2">
        {["auto", "ssh", "apache", "nginx", "windows"].map((type) => (
          <button
            key={type}
            onClick={() => setLogType(type)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              logType === type
                ? "bg-primary-600 text-white"
                : "bg-dark-card text-muted hover:text-foreground border border-dark-border"
            }`}
          >
            {type.charAt(0).toUpperCase() + type.slice(1)}
          </button>
        ))}
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept=".log,.txt,.evtx"
        label={t("logs.uploadLabel")}
        description={t("logs.uploadDescription")}
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("logs.analyzing")}</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {result && !loading && (
        <div className="mt-8 space-y-6">
          {/* Summary */}
          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-3xl font-bold">{result.total_lines}</p>
                <p className="text-sm text-muted">{t("logs.totalLines")}</p>
              </div>
              <div>
                <p className="text-3xl font-bold text-yellow-400">{result.suspicious_entries}</p>
                <p className="text-sm text-muted">{t("logs.suspicious")}</p>
              </div>
              <div>
                <p className="text-3xl font-bold text-red-400">{result.alerts.length}</p>
                <p className="text-sm text-muted">{t("logs.alerts")}</p>
              </div>
            </div>
          </div>

          {/* Timeline Chart */}
          {result.timeline.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">{t("logs.timeline")}</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={result.timeline}>
                  <XAxis dataKey="hour" stroke={chart.axis} fontSize={12} />
                  <YAxis stroke={chart.axis} fontSize={12} />
                  <Tooltip
                    contentStyle={{ background: chart.bg, border: `1px solid ${chart.border}`, borderRadius: "8px", color: chart.text }}
                    labelStyle={{ color: chart.text }}
                    cursor={{ fill: theme === "dark" ? "#ffffff12" : "#00000008" }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Alerts Table */}
          {result.alerts.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">{t("logs.alerts")}</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-muted border-b border-dark-border">
                      <th className="pb-3 pr-4">{t("logs.colSeverity")}</th>
                      <th className="pb-3 pr-4">{t("logs.colMessage")}</th>
                      <th className="pb-3 pr-4">{t("logs.colSourceIp")}</th>
                      <th className="pb-3 pr-4">{t("logs.colCountry")}</th>
                      <th className="pb-3">{t("logs.colMitre")}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-border">
                    {result.alerts.map((alert, i) => (
                      <tr key={i}>
                        <td className="py-3 pr-4">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="py-3 pr-4 text-foreground">{alert.message}</td>
                        <td className="py-3 pr-4 font-mono text-muted">{alert.source_ip ?? "-"}</td>
                        <td className="py-3 pr-4 text-muted">{alert.geo?.country ?? "-"}</td>
                        <td className="py-3 text-xs text-muted">{alert.mitre_technique ?? ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Top IPs */}
          {result.top_ips.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">{t("logs.topIps")}</h3>
              <div className="space-y-2">
                {result.top_ips.slice(0, 10).map((ip, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-dark-bg rounded-lg">
                    <span className="font-mono text-foreground">{ip.ip}</span>
                    <span className="text-red-400 font-semibold">
                      {t("logs.attempts", { n: ip.attempts })}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
