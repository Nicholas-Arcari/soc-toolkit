import { useState } from "react";
import { useTranslation } from "react-i18next";
import { FileSearch, ShieldAlert, ShieldCheck, FileWarning } from "lucide-react";
import { FileUpload, SeverityBadge } from "@sec-toolkit/common/components";
import { scanYara, type YaraScanResult } from "../api/client";

/**
 * YARA pattern-matching surface. The backend exposes a single scan
 * endpoint; UI responsibility is presenting rule matches with the
 * metadata an analyst actually reads (severity, MITRE technique,
 * reference) rather than the raw dict.
 */
export default function YaraScan() {
  const { t } = useTranslation();
  const [result, setResult] = useState<YaraScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await scanYara(file);
      setResult(data);
    } catch {
      setError(t("yara.error"));
    } finally {
      setLoading(false);
    }
  };

  const severityFor = (meta: Record<string, unknown>): string => {
    const raw = (meta.severity ?? meta.level ?? "info") as string;
    const key = String(raw).toLowerCase();
    if (["critical", "high", "medium", "low", "info"].includes(key)) return key;
    return "info";
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("yara.title")}</h1>
        <p className="text-muted mt-2">{t("yara.subtitle")}</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        label={t("yara.uploadLabel")}
        description={t("yara.uploadDescription")}
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("yara.running")}</p>
        </div>
      )}

      {error && (
        <div className="mt-8 bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {result && !loading && (
        <div className="mt-8 space-y-6">
          <div
            className={`rounded-xl border p-6 ${
              result.match_count > 0
                ? "bg-red-900/30 border-red-700"
                : "bg-green-900/30 border-green-700"
            }`}
          >
            <div className="flex items-center gap-4">
              {result.match_count > 0 ? (
                <ShieldAlert className="w-12 h-12 text-red-400" />
              ) : (
                <ShieldCheck className="w-12 h-12 text-green-400" />
              )}
              <div>
                <h2
                  className={`text-2xl font-bold ${
                    result.match_count > 0 ? "text-red-400" : "text-green-400"
                  }`}
                >
                  {result.match_count > 0
                    ? t("yara.matches", { count: result.match_count })
                    : t("yara.noMatches")}
                </h2>
                <p className="text-foreground text-sm">
                  {result.filename} · {(result.size / 1024).toFixed(1)} KB
                </p>
              </div>
            </div>
          </div>

          {result.matches.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <FileWarning className="w-5 h-5 text-yellow-400" />
                {t("yara.ruleMatches")}
              </h3>
              <div className="space-y-3">
                {result.matches.map((m) => {
                  const severity = severityFor(m.metadata);
                  const description = m.metadata.description as string | undefined;
                  const mitre = m.metadata.mitre_technique as string | undefined;
                  const reference = m.metadata.reference as string | undefined;
                  return (
                    <div
                      key={`${m.namespace}/${m.rule}`}
                      className="p-4 bg-dark-bg rounded-lg space-y-2"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <FileSearch className="w-4 h-4 text-foreground shrink-0" />
                            <span className="font-mono text-sm font-semibold truncate">
                              {m.rule}
                            </span>
                            <span className="text-xs text-muted">{m.namespace}</span>
                          </div>
                          {description && (
                            <p className="text-sm text-muted mt-1">{description}</p>
                          )}
                        </div>
                        <SeverityBadge severity={severity} />
                      </div>
                      {(m.tags.length > 0 || mitre) && (
                        <div className="flex flex-wrap gap-1">
                          {mitre && (
                            <span className="text-xs font-mono px-2 py-0.5 rounded bg-primary-900/40 text-foreground">
                              {mitre}
                            </span>
                          )}
                          {m.tags.map((tag) => (
                            <span
                              key={tag}
                              className="text-xs font-mono px-2 py-0.5 rounded bg-dark-border text-muted"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                      {reference && (
                        <a
                          href={reference}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-foreground hover:underline"
                        >
                          {reference}
                        </a>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
