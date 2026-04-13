import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import FileUpload from "../components/common/FileUpload";
import SeverityBadge from "../components/common/SeverityBadge";
import { analyzeLogs, type LogAnalysisResult } from "../api/client";

export default function LogAnalyzer() {
  const [result, setResult] = useState<LogAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logType, setLogType] = useState("auto");

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeLogs(file, logType);
      setResult(data);
    } catch {
      setError("Analysis failed. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Log Analyzer</h1>
        <p className="text-gray-400 mt-2">Upload log files for automated threat detection</p>
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
                : "bg-dark-card text-gray-400 hover:text-white border border-dark-border"
            }`}
          >
            {type.charAt(0).toUpperCase() + type.slice(1)}
          </button>
        ))}
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept=".log,.txt,.evtx"
        label="Upload Log File"
        description="Supports auth.log, access.log, Windows Security events"
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-gray-400 mt-4">Analyzing logs...</p>
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
                <p className="text-sm text-gray-400">Total Lines</p>
              </div>
              <div>
                <p className="text-3xl font-bold text-yellow-400">{result.suspicious_entries}</p>
                <p className="text-sm text-gray-400">Suspicious</p>
              </div>
              <div>
                <p className="text-3xl font-bold text-red-400">{result.alerts.length}</p>
                <p className="text-sm text-gray-400">Alerts</p>
              </div>
            </div>
          </div>

          {/* Timeline Chart */}
          {result.timeline.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">Activity Timeline</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={result.timeline}>
                  <XAxis dataKey="hour" stroke="#94a3b8" fontSize={12} />
                  <YAxis stroke="#94a3b8" fontSize={12} />
                  <Tooltip
                    contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                    labelStyle={{ color: "#e2e8f0" }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Alerts Table */}
          {result.alerts.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">Alerts</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-400 border-b border-dark-border">
                      <th className="pb-3 pr-4">Severity</th>
                      <th className="pb-3 pr-4">Message</th>
                      <th className="pb-3 pr-4">Source IP</th>
                      <th className="pb-3 pr-4">Country</th>
                      <th className="pb-3">MITRE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-border">
                    {result.alerts.map((alert, i) => (
                      <tr key={i}>
                        <td className="py-3 pr-4">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="py-3 pr-4 text-gray-300">{alert.message}</td>
                        <td className="py-3 pr-4 font-mono text-gray-400">{alert.source_ip ?? "-"}</td>
                        <td className="py-3 pr-4 text-gray-400">{alert.geo?.country ?? "-"}</td>
                        <td className="py-3 text-xs text-gray-500">{alert.mitre_technique ?? ""}</td>
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
              <h3 className="text-lg font-semibold mb-4">Top Source IPs</h3>
              <div className="space-y-2">
                {result.top_ips.slice(0, 10).map((ip, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-dark-bg rounded-lg">
                    <span className="font-mono text-gray-300">{ip.ip}</span>
                    <span className="text-red-400 font-semibold">{ip.attempts} attempts</span>
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
