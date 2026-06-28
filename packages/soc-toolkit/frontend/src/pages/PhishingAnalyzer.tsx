import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Mail, AlertTriangle, CheckCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import { FileUpload, SeverityBadge } from "@sec-toolkit/common/components";
import {
  analyzePhishing,
  triageInbox,
  type InboxMessage,
  type PhishingResult,
} from "../api/client";

export default function PhishingAnalyzer() {
  const { t } = useTranslation();
  const [result, setResult] = useState<PhishingResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inbox, setInbox] = useState({
    host: "",
    username: "",
    password: "",
    folder: "INBOX",
  });
  const [inboxMsgs, setInboxMsgs] = useState<InboxMessage[] | null>(null);
  const [inboxLoading, setInboxLoading] = useState(false);
  const [inboxError, setInboxError] = useState<string | null>(null);

  async function handleInbox(e: FormEvent) {
    e.preventDefault();
    setInboxLoading(true);
    setInboxError(null);
    setInboxMsgs(null);
    try {
      setInboxMsgs(await triageInbox(inbox));
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setInboxError(detail ?? t("phishing.inbox.error"));
    } finally {
      setInboxLoading(false);
    }
  }

  const handleFileSelect = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await analyzePhishing(file);
      setResult(data);
    } catch {
      setError(t("phishing.error"));
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

  const inboxFields = [
    ["host", "text", "off"],
    ["username", "text", "username"],
    ["password", "password", "current-password"],
    ["folder", "text", "off"],
  ] as const;

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("phishing.title")}</h1>
        <p className="text-muted mt-2">{t("phishing.subtitle")}</p>
      </div>

      <FileUpload
        onFileSelect={handleFileSelect}
        accept=".eml"
        label={t("phishing.uploadLabel")}
        description={t("phishing.uploadDescription")}
      />

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("phishing.analyzing")}</p>
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
                    <p className="text-foreground">
                      {t("phishing.riskConfidence", {
                        score: result.risk_score,
                        confidence: (result.confidence * 100).toFixed(0),
                      })}
                    </p>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Indicators */}
          {result.indicators.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">
                {t("phishing.indicators")}
              </h3>
              <ul className="space-y-2">
                {result.indicators.map((indicator, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
                    <span className="text-foreground">{indicator}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* URLs */}
          {result.urls.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">
                {t("phishing.urlsFound", { n: result.urls.length })}
              </h3>
              <div className="space-y-3">
                {result.urls.map((url, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-dark-bg rounded-lg">
                    <span className="text-sm font-mono text-foreground truncate flex-1">{url.url}</span>
                    <SeverityBadge severity={url.malicious ? "critical" : "info"} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h3 className="text-lg font-semibold mb-4">
                {t("phishing.recommendations")}
              </h3>
              <ul className="space-y-2">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-foreground mt-0.5 shrink-0" />
                    <span className="text-foreground">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <section className="mt-10 border-t border-border pt-6">
        <h2 className="text-lg font-semibold text-foreground mb-1">
          {t("phishing.inbox.title")}
        </h2>
        <p className="text-sm text-muted mb-4">{t("phishing.inbox.subtitle")}</p>
        <form
          onSubmit={handleInbox}
          className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-2xl"
        >
          {inboxFields.map(([field, type, autoComplete]) => (
            <input
              key={field}
              type={type}
              autoComplete={autoComplete}
              value={inbox[field]}
              onChange={(e) => setInbox({ ...inbox, [field]: e.target.value })}
              placeholder={t(`phishing.inbox.${field}`)}
              className="rounded-lg bg-background border border-border px-3 py-2 text-sm text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
            />
          ))}
          <button
            type="submit"
            disabled={
              inboxLoading ||
              !inbox.host.trim() ||
              !inbox.username.trim() ||
              !inbox.password
            }
            className="sm:col-span-2 rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium py-2.5 transition-opacity"
          >
            {inboxLoading
              ? t("phishing.inbox.triaging")
              : t("phishing.inbox.triageButton")}
          </button>
        </form>

        {inboxError && (
          <div
            role="alert"
            className="mt-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-3 py-2"
          >
            {inboxError}
          </div>
        )}

        {inboxMsgs && (
          <table className="w-full text-sm mt-4">
            <thead>
              <tr className="text-left text-xs text-muted border-b border-border">
                <th className="py-2 pr-4">{t("phishing.inbox.colFromSubject")}</th>
                <th className="py-2 pr-4">{t("phishing.inbox.colVerdict")}</th>
                <th className="py-2">{t("phishing.inbox.colScore")}</th>
              </tr>
            </thead>
            <tbody>
              {inboxMsgs.length === 0 ? (
                <tr>
                  <td colSpan={3} className="py-3 text-muted">
                    {t("phishing.inbox.empty", {
                      folder: inbox.folder || "INBOX",
                    })}
                  </td>
                </tr>
              ) : (
                inboxMsgs.map((m, i) => (
                  <tr key={i} className="border-b border-border/50 align-top">
                    <td className="py-2 pr-4 max-w-md">
                      <div className="text-foreground truncate">
                        {m.subject || t("phishing.inbox.noSubject")}
                      </div>
                      <div className="text-xs text-muted truncate">{m.from}</div>
                    </td>
                    <td className="py-2 pr-4 capitalize">
                      <span
                        className={
                          m.verdict === "malicious"
                            ? "text-red-400"
                            : m.verdict === "suspicious"
                              ? "text-amber-400"
                              : "text-emerald-400"
                        }
                      >
                        {m.verdict}
                      </span>
                    </td>
                    <td className="py-2">{m.risk_score}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
