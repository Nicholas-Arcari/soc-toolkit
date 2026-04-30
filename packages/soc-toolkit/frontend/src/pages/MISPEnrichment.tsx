import { useState } from "react";
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
  const [text, setText] = useState(SAMPLE_TEXT);
  const [result, setResult] = useState<MISPEnrichmentResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runEnrich() {
    setError(null);
    setResult(null);
    if (!text.trim()) {
      setError("Paste a report or free-form text first.");
      return;
    }
    setLoading(true);
    try {
      const data = await enrichWithMISP(text);
      setResult(data);
    } catch {
      setError("Enrichment failed. Is the backend running?");
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
        <h1 className="text-3xl font-bold">MISP Enrichment</h1>
        <p className="text-gray-400 mt-2">
          Paste a threat report; the toolkit extracts IOCs and checks each one
          against the configured MISP instance so novel indicators surface over
          the ones already known to the community.
        </p>
      </div>

      <div className="bg-dark-card rounded-xl border border-dark-border p-6 space-y-4">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={10}
          spellCheck={false}
          placeholder="Paste report, incident summary, or free-form text here…"
          className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-3 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary-500"
        />
        <div className="flex items-center justify-between">
          <p className="text-xs text-gray-500">
            IOCs are extracted locally; only confirmed IOC values are sent to MISP.
          </p>
          <button
            onClick={runEnrich}
            disabled={loading}
            className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:bg-gray-700 text-white rounded-lg text-sm font-medium flex items-center gap-2"
          >
            <Share2 className="w-4 h-4" />
            {loading ? "Enriching…" : "Extract + enrich"}
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
                <strong className="text-amber-300">MISP is not configured.</strong>{" "}
                <span className="text-amber-200/80">
                  Set <span className="font-mono">MISP_URL</span> and{" "}
                  <span className="font-mono">MISP_API_KEY</span> in your .env to see
                  enrichment results. Extraction still works below.
                </span>
              </div>
            </div>
          )}

          <div className="grid grid-cols-3 gap-3">
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-xs uppercase text-gray-500">Extracted</p>
              <p className="text-2xl font-bold mt-1">{result.extracted_count}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-xs uppercase text-gray-500">Known to MISP</p>
              <p className="text-2xl font-bold text-amber-400 mt-1">
                {result.misp.known_count}
              </p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-xs uppercase text-gray-500">Novel</p>
              <p className="text-2xl font-bold text-primary-400 mt-1">
                {Math.max(
                  0,
                  result.extracted_count - result.misp.known_count,
                )}
              </p>
            </div>
          </div>

          {Object.keys(result.misp.summary).length > 0 && (
            <div className="bg-dark-card border border-dark-border rounded-xl p-6">
              <h3 className="font-semibold mb-3">Coverage by kind</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                {Object.entries(result.misp.summary).map(([kind, stats]) => (
                  <div
                    key={kind}
                    className="flex justify-between bg-dark-bg rounded-lg px-3 py-2"
                  >
                    <span className="text-gray-300 font-mono">{kind}</span>
                    <span className="text-gray-500">
                      {stats.known} / {stats.checked}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="bg-dark-card border border-dark-border rounded-xl p-6">
            <h3 className="font-semibold mb-3">Extracted indicators</h3>
            {result.iocs.length === 0 && (
              <p className="text-gray-500 text-sm">
                No IOCs found in the provided text.
              </p>
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
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-dark-border text-gray-400 shrink-0">
                          {ioc.type}
                        </span>
                        <span className="font-mono text-sm truncate">{ioc.value}</span>
                      </div>
                      {known && lookup?.events && lookup.events.length > 0 && (
                        <ul className="mt-1 text-xs text-gray-400 space-y-0.5">
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
                      <span className="text-xs text-gray-600 shrink-0">-</span>
                    ) : known ? (
                      <span className="text-xs text-amber-400 flex items-center gap-1 shrink-0">
                        <CheckCircle className="w-3 h-3" />
                        Known
                      </span>
                    ) : (
                      <span className="text-xs text-gray-500 flex items-center gap-1 shrink-0">
                        <XCircle className="w-3 h-3" />
                        Novel
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
