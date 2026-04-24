import { useState } from "react";
import { Mail, AlertTriangle, CheckCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import FileUpload from "../components/common/FileUpload";
import SeverityBadge from "../components/common/SeverityBadge";
import { analyzePhishing, type PhishingResult } from "../api/client";

export default function PhishingAnalyzer() {
  const [result, setResult] = useState<PhishingResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await analyzePhishing(file);
      setResult(data);
    } catch (err) {
      setError("Analysis failed. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const verdictConfig: Record<string, { icon: typeof ShieldAlert; color: string; bg: string }> = {
    MALICIOUS: { icon: ShieldAlert, color: "text-red-400", bg: "bg-red-900/30 border-red-700" },
    SUSPICIOUS: { icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-900/30 border-yellow-700" },
    CAUTIOUS: { icon: Mail, color: "text-blue-400", bg: "bg-blue-900/30 border-blue-700" },
    CLEAN: { icon: ShieldCheck, color: "text-green-400", bg: "bg-green-900/30 border-green-700" },
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Phishing Analyzer</h1>
        <p className="text-gray-400 mt-2">Upload an .eml file for automated phishing analysis</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept=".eml"
        label="Upload Email File (.eml)"
        description="Drag and drop an .eml file or click to browse"
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-gray-400 mt-4">Analyzing email...</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {result && !loading && (
        <div className="mt-8 space-y-6">
          {/* Verdict */}
          {(() => {
            const config = verdictConfig[result.verdict] ?? verdictConfig.SUSPICIOUS;
            const VerdictIcon = config.icon;
            return (
              <div className={`rounded-xl border p-6 ${config.bg}`}>
                <div className="flex items-center gap-4">
                  <VerdictIcon className={`w-12 h-12 ${config.color}`} />
                  <div>
                    <h2 className={`text-2xl font-bold ${config.color}`}>{result.verdict}</h2>
                    <p className="text-gray-300">
                      Risk Score: {result.risk_score}/100 | Confidence: {(result.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Indicators */}
          {result.indicators.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">Indicators</h3>
              <ul className="space-y-2">
                {result.indicators.map((indicator, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
                    <span className="text-gray-300">{indicator}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* URLs */}
          {result.urls.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">URLs Found ({result.urls.length})</h3>
              <div className="space-y-3">
                {result.urls.map((url, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-dark-bg rounded-lg">
                    <span className="text-sm font-mono text-gray-300 truncate flex-1">{url.url}</span>
                    <SeverityBadge severity={url.malicious ? "critical" : "info"} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">Recommendations</h3>
              <ul className="space-y-2">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-primary-400 mt-0.5 shrink-0" />
                    <span className="text-gray-300">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
