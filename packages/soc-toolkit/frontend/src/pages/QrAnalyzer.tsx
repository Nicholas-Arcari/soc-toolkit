import { useState } from "react";
import { useTranslation } from "react-i18next";
import ExportButtons from "../components/common/ExportButtons";
import { FileUpload } from "@sec-toolkit/common/components";
import { AlertTriangle, CheckCircle, Link2, QrCode } from "lucide-react";
import {
  analyzeQrPayload,
  decodeQrFromImageFile,
  type QrAnalysis,
} from "../lib/qr";
import { awardXp, checkUrl, type UrlCheckResult } from "../api/client";

export default function QrAnalyzer() {
  const { t } = useTranslation();
  const [analysis, setAnalysis] = useState<QrAnalysis | null>(null);
  const [urlResult, setUrlResult] = useState<UrlCheckResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);

  async function handleFileSelect(file: File) {
    setLoading(true);
    setError(null);
    setAnalysis(null);
    setUrlResult(null);
    setNotFound(false);
    try {
      const payload = await decodeQrFromImageFile(file);
      if (!payload) {
        setNotFound(true);
        return;
      }
      const result = analyzeQrPayload(payload);
      setAnalysis(result);

      let threat = 0;
      if (result.kind === "url") {
        try {
          const reputation = await checkUrl(payload);
          setUrlResult(reputation);
          if (reputation?.malicious) threat = 1;
        } catch {
          // reputation is best-effort; the local flags still stand
        }
      }
      awardXp("qr", result.flags.length + threat);
    } catch {
      setError(t("qr.readError"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">{t("qr.title")}</h1>
        <p className="text-muted mt-2">{t("qr.subtitle")}</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept="image/*"
        label={t("qr.uploadLabel")}
        description={t("qr.uploadDescription")}
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("qr.decoding")}</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {notFound && !loading && (
        <div className="mt-8 bg-card border border-border rounded-xl p-6 text-muted">
          {t("qr.notFound")}
        </div>
      )}

      {analysis && !loading && (
        <div className="mt-8 space-y-6">
          <div className="flex justify-end">
            <ExportButtons data={analysis} reportType="qr" />
          </div>
          <div className="bg-card border border-border rounded-xl p-6 space-y-3">
            <div className="flex items-center gap-2">
              <QrCode className="w-5 h-5 text-indigo-400" />
              <span className="text-xs uppercase tracking-wide text-muted">
                {analysis.kind}
              </span>
            </div>
            <p className="font-mono text-sm text-foreground break-all">
              {analysis.payload}
            </p>
            {analysis.flags.length > 0 ? (
              <ul className="space-y-1.5 pt-1">
                {analysis.flags.map((flag) => (
                  <li
                    key={flag}
                    className="flex items-start gap-2 text-sm text-amber-400"
                  >
                    <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                    {flag}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="flex items-center gap-2 text-sm text-green-400">
                <CheckCircle className="w-4 h-4" />
                {t("qr.noFlags")}
              </p>
            )}
          </div>

          {urlResult && (
            <div className="bg-card border border-border rounded-xl p-6 space-y-3">
              <h3 className="font-semibold text-foreground flex items-center gap-2">
                <Link2 className="w-4 h-4 text-muted" />
                {t("urlCheck.reputation")}
              </h3>
              <span
                className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border text-sm font-medium ${
                  urlResult.malicious
                    ? "text-red-400 bg-red-500/10 border-red-500/30"
                    : "text-green-400 bg-green-500/10 border-green-500/30"
                }`}
              >
                {urlResult.malicious ? (
                  <AlertTriangle className="w-4 h-4" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                {urlResult.malicious
                  ? t("urlCheck.flaggedMalicious")
                  : t("urlCheck.noDetections")}
              </span>
              {urlResult.suspicious_patterns.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {urlResult.suspicious_patterns.map((pattern) => (
                    <span
                      key={pattern}
                      className="px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/30 text-xs"
                    >
                      {pattern}
                    </span>
                  ))}
                </div>
              )}
              <p className="text-xs text-muted">{t("urlCheck.checkedAgainst")}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
