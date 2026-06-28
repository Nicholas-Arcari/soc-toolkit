import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Share2,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Radio,
  Info,
} from "lucide-react";
import { enrichWithMISP, type MISPEnrichmentResponse } from "../api/client";

const SAMPLE_TEXT = `Observed callback to 185.220.101.42 over port 443.
Dropper hash: 44d88612fea8a8f36de82e1278abb02f
Phishing sender: finance@acme-payroll[.]support
Domain: evil-update[.]xyz`;

/**
 * Paste-a-report workflow: text goes in, IOCs come out, each tagged
 * with MISP status. The page's job is making "known to MISP" obvious
 * at a glance so the analyst knows which indicators to skip
 * investigating and which are novel.
 */
export default function MISPEnrichment() {
  const { t } = useTranslation();
  const [text, setText] = useState(SAMPLE_TEXT);
  const [result, setResult] = useState<MISPEnrichmentResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runEnrich() {
    setError(null);
    setResult(null);
    if (!text.trim()) {
      setError(t("misp.pasteFirst"));
      return;
    }
    setLoading(true);
    try {
      const data = await enrichWithMISP(text);
      setResult(data);
    } catch {
      setError(t("misp.enrichError"));
    } finally {
      setLoading(false);
    }
  }

  const mispUnavailable =
    result &&
    Object.values(result.misp.results).every(
      (r) => r.error === "MISP not configured",
    );

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("misp.title")}</h1>
        <p className="text-muted mt-2">{t("misp.subtitle")}</p>
      </div>

      <div className="bg-dark-card rounded-xl border border-dark-border p-6 space-y-4">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={10}
          spellCheck={false}
          placeholder={t("misp.placeholder")}
          className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-3 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary-500"
        />
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted">{t("misp.hint")}</p>
          <button
            onClick={runEnrich}
            disabled={loading}
            className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium flex items-center gap-2"
          >
            <Share2 className="w-4 h-4" />
            {loading ? t("misp.enriching") : t("misp.extractEnrich")}
          </button>
        </div>
        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-950/40 border border-red-900/40 rounded-lg px-3 py-2">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        )}
      </div>

      {result && (
        <div className="mt-6 space-y-4">
          {mispUnavailable && (
            <div className="bg-amber-950/40 border border-amber-900/40 rounded-lg p-4 text-sm flex items-start gap-2">
              <Info className="w-4 h-4 text-amber-300 mt-0.5 shrink-0" />
              <div>
                <strong className="text-amber-300">{t("misp.notConfiguredTitle")}</strong>{" "}
                <span className="text-amber-200/80">{t("misp.notConfiguredBody")}</span>
              </div>
            </div>
          )}

          <div className="grid grid-cols-3 gap-3">
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-xs uppercase text-muted">{t("misp.extracted")}</p>
              <p className="text-2xl font-bold mt-1">{result.extracted_count}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-xs uppercase text-muted">{t("misp.knownToMisp")}</p>
              <p className="text-2xl font-bold text-amber-400 mt-1">
                {result.misp.known_count}
              </p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-xs uppercase text-muted">{t("misp.novel")}</p>
              <p className="text-2xl font-bold text-foreground mt-1">
                {Math.max(
                  0,
                  result.extracted_count - result.misp.known_count,
                )}
              </p>
            </div>
          </div>

          {Object.keys(result.misp.summary).length > 0 && (
            <div className="bg-dark-card border border-dark-border rounded-xl p-6">
              <h3 className="font-semibold mb-3">{t("misp.coverageByKind")}</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                {Object.entries(result.misp.summary).map(([kind, stats]) => (
                  <div
                    key={kind}
                    className="flex justify-between bg-dark-bg rounded-lg px-3 py-2"
                  >
                    <span className="text-foreground font-mono">{kind}</span>
                    <span className="text-muted">
                      {stats.known} / {stats.checked}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="bg-dark-card border border-dark-border rounded-xl p-6">
            <h3 className="font-semibold mb-3">{t("misp.extractedIndicators")}</h3>
            {result.iocs.length === 0 && (
              <p className="text-muted text-sm">{t("misp.noIocs")}</p>
            )}
            <div className="space-y-2">
              {result.iocs.map((ioc, i) => {
                const lookup = result.misp.results[ioc.value];
                const known = lookup?.found === true;
                const unavailable = lookup?.error === "MISP not configured";
                return (
                  <div
                    key={`${ioc.type}-${ioc.value}-${i}`}
                    className="flex items-start justify-between gap-4 p-3 bg-dark-bg rounded-lg"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-dark-border text-muted shrink-0">
                          {ioc.type}
                        </span>
                        <span className="font-mono text-sm truncate">{ioc.value}</span>
                      </div>
                      {known && lookup?.events && lookup.events.length > 0 && (
                        <ul className="mt-1 text-xs text-muted space-y-0.5">
                          {lookup.events.slice(0, 3).map((ev, j) => (
                            <li key={j}>
                              <Radio className="inline w-3 h-3 mr-1 text-amber-400" />
                              <span className="font-mono">#{ev.event_id}</span> · {ev.info}
                              {ev.to_ids && (
                                <span className="ml-1 text-red-400">(to_ids)</span>
                              )}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                    {unavailable ? (
                      <span className="text-xs text-muted shrink-0">-</span>
                    ) : known ? (
                      <span className="text-xs text-amber-400 flex items-center gap-1 shrink-0">
                        <CheckCircle className="w-3 h-3" />
                        {t("misp.known")}
                      </span>
                    ) : (
                      <span className="text-xs text-muted flex items-center gap-1 shrink-0">
                        <XCircle className="w-3 h-3" />
                        {t("misp.novelTag")}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
