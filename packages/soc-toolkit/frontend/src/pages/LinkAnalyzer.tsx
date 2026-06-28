import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import ExportButtons from "../components/common/ExportButtons";
import CopyButton from "../components/common/CopyButton";
import PivotLink from "../components/common/PivotLink";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  Link2,
  Search,
} from "lucide-react";
import {
  awardXp,
  checkUrl,
  traceUrl,
  type RedirectTrace,
  type UrlCheckResult,
} from "../api/client";
import { hostFromUrl, urlRiskFlags } from "../lib/url";

export default function LinkAnalyzer() {
  const { t } = useTranslation();
  const [input, setInput] = useState("");
  const [trace, setTrace] = useState<RedirectTrace | null>(null);
  const [reputation, setReputation] = useState<UrlCheckResult | null>(null);
  const [flags, setFlags] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bulkInput, setBulkInput] = useState("");
  const [bulkRows, setBulkRows] = useState<{ url: string; flags: string[] }[]>(
    [],
  );

  function runBulk() {
    const urls = bulkInput
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 50);
    setBulkRows(urls.map((url) => ({ url, flags: urlRiskFlags(url) })));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const url = input.trim();
    if (!url) return;
    setLoading(true);
    setError(null);
    setTrace(null);
    setReputation(null);
    setFlags([]);
    try {
      const result = await traceUrl(url);
      setTrace(result);
      const localFlags = urlRiskFlags(result.final_url);
      setFlags(localFlags);

      let threat = 0;
      if (!result.blocked) {
        try {
          const rep = await checkUrl(result.final_url);
          setReputation(rep);
          if (rep?.malicious) threat = 1;
        } catch {
          // reputation is best-effort; the trace + flags still stand
        }
      }
      awardXp("link", localFlags.length + result.hops + threat);
    } catch {
      setError(t("link.error"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-3xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">{t("link.title")}</h1>
        <p className="text-muted mt-2">{t("link.subtitle")}</p>
      </div>

      <form onSubmit={onSubmit} className="flex gap-2">
        <input
          type="url"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={t("link.placeholder")}
          className="flex-1 rounded-lg bg-background border border-border px-3 py-2 text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60 focus:border-emerald-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg bg-foreground text-background hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium px-4 py-2 transition-opacity"
        >
          <Search className="w-4 h-4" />
          {t("link.analyze")}
        </button>
      </form>

      {error && (
        <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400">
          {error}
        </div>
      )}

      {loading && (
        <div className="mt-8 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("link.tracing")}</p>
        </div>
      )}

      {trace && !loading && (
        <div className="mt-8 space-y-6">
          <div className="flex justify-end">
            <ExportButtons data={trace} reportType="link" />
          </div>
          {trace.error && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-amber-400 text-sm">
              {trace.error}
            </div>
          )}

          <div className="bg-card border border-border rounded-xl p-6">
            <h3 className="font-semibold text-foreground mb-4">
              {t("link.redirectChain")}
              <span className="text-muted font-normal text-sm">
                {" "}
                · {t("link.hops", { count: trace.hops })}
              </span>
            </h3>
            <ol className="space-y-2">
              {trace.chain.map((hop, i) => (
                <li
                  key={`${hop.url}-${i}`}
                  className="flex items-start gap-3 text-sm"
                >
                  <span className="font-mono text-xs text-muted shrink-0 w-10 text-right">
                    {hop.status}
                  </span>
                  <ArrowRight className="w-4 h-4 text-muted shrink-0 mt-0.5" />
                  <span className="font-mono text-foreground break-all">
                    {hop.url}
                  </span>
                </li>
              ))}
              {trace.chain.length === 0 && (
                <li className="text-sm text-muted">{t("link.noHops")}</li>
              )}
            </ol>
            {!trace.blocked && trace.chain.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border">
                <p className="text-xs text-muted mb-1">
                  {t("link.finalDestination")}
                </p>
                <div className="flex items-start gap-1.5">
                  <p className="font-mono text-sm text-foreground break-all">
                    {trace.final_url}
                  </p>
                  <CopyButton
                    value={trace.final_url}
                    label={t("link.copyFinalUrl")}
                    className="shrink-0 mt-0.5"
                  />
                  <PivotLink
                    value={hostFromUrl(trace.final_url)}
                    className="shrink-0 mt-0.5"
                  />
                </div>
              </div>
            )}
          </div>

          {flags.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-6">
              <h3 className="font-semibold text-foreground mb-3">
                {t("link.riskFlags")}
              </h3>
              <ul className="space-y-1.5">
                {flags.map((flag) => (
                  <li
                    key={flag}
                    className="flex items-start gap-2 text-sm text-amber-400"
                  >
                    <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                    {flag}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {reputation && (
            <div className="bg-card border border-border rounded-xl p-6 space-y-3">
              <h3 className="font-semibold text-foreground flex items-center gap-2">
                <Link2 className="w-4 h-4 text-muted" />
                {t("urlCheck.reputation")}
              </h3>
              <span
                className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border text-sm font-medium ${
                  reputation.malicious
                    ? "text-red-400 bg-red-500/10 border-red-500/30"
                    : "text-green-400 bg-green-500/10 border-green-500/30"
                }`}
              >
                {reputation.malicious ? (
                  <AlertTriangle className="w-4 h-4" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                {reputation.malicious
                  ? t("urlCheck.flaggedMalicious")
                  : t("urlCheck.noDetections")}
              </span>
              <p className="text-xs text-muted">{t("urlCheck.checkedAgainst")}</p>
            </div>
          )}
        </div>
      )}

      <section className="mt-10 border-t border-border pt-6">
        <h2 className="text-sm font-semibold text-foreground mb-1">
          {t("link.bulkTitle")}
        </h2>
        <p className="text-xs text-muted mb-3">{t("link.bulkSubtitle")}</p>
        <textarea
          value={bulkInput}
          onChange={(e) => setBulkInput(e.target.value)}
          rows={4}
          placeholder={"https://bit.ly/x\nhttp://192.168.0.1/login"}
          className="w-full rounded-lg bg-background border border-border px-3 py-2 text-sm font-mono text-foreground placeholder-muted focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
        />
        <button
          type="button"
          onClick={runBulk}
          className="mt-2 rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium px-4 py-2"
        >
          {t("link.triageButton")}
        </button>
        {bulkRows.length > 0 && (
          <table className="w-full text-sm mt-4">
            <thead>
              <tr className="text-left text-xs text-muted border-b border-border">
                <th className="py-2 pr-4">{t("link.colUrl")}</th>
                <th className="py-2">{t("link.colFlags")}</th>
              </tr>
            </thead>
            <tbody>
              {bulkRows.map((row, i) => (
                <tr key={i} className="border-b border-border/50 align-top">
                  <td className="py-2 pr-4 font-mono text-xs text-foreground break-all max-w-xs">
                    {row.url}
                  </td>
                  <td className="py-2">
                    {row.flags.length === 0 ? (
                      <span className="text-xs text-emerald-400">
                        {t("link.noFlags")}
                      </span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {row.flags.map((flag) => (
                          <span
                            key={flag}
                            className="text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30"
                          >
                            {flag}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
