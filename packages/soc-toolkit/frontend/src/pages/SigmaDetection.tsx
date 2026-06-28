import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Library, PlayCircle, AlertTriangle, BookOpen, Terminal, Copy, Check } from "lucide-react";
import { SeverityBadge } from "@sec-toolkit/common/components";
import {
  compileSigmaRule,
  evaluateSigma,
  listSigmaRules,
  type SigmaBackend,
  type SigmaCompileResult,
  type SigmaEvaluationResult,
  type SigmaRuleList,
} from "../api/client";

type Tab = "library" | "evaluate";

const BACKENDS: { id: SigmaBackend; label: string }[] = [
  { id: "splunk", label: "Splunk SPL" },
  { id: "lucene", label: "Elasticsearch" },
  { id: "kql", label: "KQL / Sentinel" },
];

const SAMPLE_EVENTS = `[
  {
    "event_type": "ssh_login",
    "source_ip": "10.0.0.42",
    "username": "root",
    "auth_result": "failed",
    "timestamp": "2026-01-12T03:14:00Z"
  }
]`;

/**
 * Two-mode page: "Library" inspects the bundled Sigma corpus,
 * "Evaluate" runs it against user-provided events. The library view
 * matters on its own - analysts need to know what coverage they
 * have before they trust a "no matches" result.
 */
export default function SigmaDetection() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("library");
  const [rules, setRules] = useState<SigmaRuleList | null>(null);
  const [rulesError, setRulesError] = useState<string | null>(null);

  const [eventsText, setEventsText] = useState(SAMPLE_EVENTS);
  const [result, setResult] = useState<SigmaEvaluationResult | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    listSigmaRules()
      .then(setRules)
      .catch(() => setRulesError(t("sigma.rulesError")));
  }, [t]);

  async function runEvaluate() {
    setEvalError(null);
    setResult(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(eventsText);
    } catch {
      setEvalError(t("sigma.invalidJson"));
      return;
    }
    if (!Array.isArray(parsed)) {
      setEvalError(t("sigma.mustBeArray"));
      return;
    }
    setLoading(true);
    try {
      const data = await evaluateSigma(parsed as Record<string, unknown>[]);
      setResult(data);
    } catch {
      setEvalError(t("sigma.evalFailed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("sigma.title")}</h1>
        <p className="text-muted mt-2">{t("sigma.subtitle")}</p>
      </div>

      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setTab("library")}
          className={`px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 ${
            tab === "library"
              ? "bg-primary-600/30 text-foreground"
              : "bg-dark-card text-muted hover:text-foreground"
          }`}
        >
          <Library className="w-4 h-4" />
          {t("sigma.ruleLibrary")} {rules ? `(${rules.rule_count})` : ""}
        </button>
        <button
          onClick={() => setTab("evaluate")}
          className={`px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 ${
            tab === "evaluate"
              ? "bg-primary-600/30 text-foreground"
              : "bg-dark-card text-muted hover:text-foreground"
          }`}
        >
          <PlayCircle className="w-4 h-4" />
          {t("sigma.evaluateEvents")}
        </button>
      </div>

      {tab === "library" && (
        <div className="bg-dark-card rounded-xl border border-dark-border p-6">
          {rulesError && (
            <div className="text-red-400 text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {rulesError}
            </div>
          )}
          {!rules && !rulesError && (
            <p className="text-muted text-sm">{t("sigma.loadingRules")}</p>
          )}
          {rules && (
            <div className="space-y-3">
              {rules.rules.map((r) => (
                <RuleCard key={r.id} rule={r} />
              ))}
            </div>
          )}
        </div>
      )}

      {tab === "evaluate" && (
        <div className="space-y-4">
          <div className="bg-dark-card rounded-xl border border-dark-border p-6 space-y-4">
            <label htmlFor="sigma-events-input" className="block text-sm font-medium text-foreground">
              {t("sigma.eventsLabel")}
            </label>
            <textarea
              id="sigma-events-input"
              value={eventsText}
              onChange={(e) => setEventsText(e.target.value)}
              rows={12}
              spellCheck={false}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-3 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted">{t("sigma.eventsHint")}</p>
              <button
                onClick={runEvaluate}
                disabled={loading}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium flex items-center gap-2"
              >
                <PlayCircle className="w-4 h-4" />
                {loading ? t("sigma.evaluating") : t("sigma.evaluate")}
              </button>
            </div>
            {evalError && (
              <div className="flex items-center gap-2 text-red-400 text-sm bg-red-950/40 border border-red-900/40 rounded-lg px-3 py-2">
                <AlertTriangle className="w-4 h-4" />
                {evalError}
              </div>
            )}
          </div>

          {result && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6 space-y-3">
              <h3 className="font-semibold">
                {t("sigma.resultSummary", {
                  matches: result.match_count,
                  events: result.event_count,
                })}
              </h3>
              {result.matches.length === 0 && (
                <p className="text-muted text-sm">{t("sigma.noTrigger")}</p>
              )}
              {result.matches.map((m, i) => (
                <div
                  key={`${m.rule_id}-${i}`}
                  className="p-4 bg-dark-bg rounded-lg space-y-2"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="font-semibold">{m.title}</div>
                      <p className="text-xs text-muted font-mono mt-0.5">{m.rule_id}</p>
                      {m.description && (
                        <p className="text-sm text-muted mt-1">{m.description}</p>
                      )}
                    </div>
                    <SeverityBadge severity={m.level || "info"} />
                  </div>
                  {m.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1">
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
                  <details className="text-xs">
                    <summary className="cursor-pointer text-muted hover:text-foreground">
                      {t("sigma.event")}
                    </summary>
                    <pre className="mt-2 p-2 bg-black/30 rounded text-foreground font-mono overflow-x-auto">
                      {JSON.stringify(m.event, null, 2)}
                    </pre>
                  </details>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Library row with an expandable "Compile to SIEM" panel. Kept inline
 * in this file so the page stays single-import - the panel is narrow
 * in scope (one rule, three backends) and doesn't need its own module.
 */
function RuleCard({ rule }: { rule: { id: string; title: string; description?: string; level?: string; tags: string[] } }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [backend, setBackend] = useState<SigmaBackend>("splunk");
  const [result, setResult] = useState<SigmaCompileResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  async function runCompile(target: SigmaBackend) {
    setBackend(target);
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const data = await compileSigmaRule(rule.id, target);
      setResult(data);
    } catch {
      setError(t("sigma.compileFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function copyQuery() {
    if (!result) return;
    await navigator.clipboard.writeText(result.query);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="p-4 bg-dark-bg rounded-lg space-y-2">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-foreground shrink-0" />
            <span className="font-semibold truncate">{rule.title}</span>
          </div>
          {rule.description && (
            <p className="text-sm text-muted mt-1">{rule.description}</p>
          )}
          <p className="text-xs text-muted font-mono mt-1">{rule.id}</p>
        </div>
        <SeverityBadge severity={rule.level || "info"} />
      </div>
      {rule.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {rule.tags.map((tag) => (
            <span
              key={tag}
              className="text-xs font-mono px-2 py-0.5 rounded bg-dark-border text-muted"
            >
              {tag}
            </span>
          ))}
        </div>
      )}
      <div>
        <button
          onClick={() => setOpen((v) => !v)}
          className="text-xs text-foreground hover:text-foreground flex items-center gap-1 mt-1"
        >
          <Terminal className="w-3.5 h-3.5" />
          {open ? t("sigma.hideQuery") : t("sigma.compileQuery")}
        </button>
      </div>
      {open && (
        <div className="pt-3 space-y-2 border-t border-dark-border">
          <div className="flex flex-wrap gap-2">
            {BACKENDS.map((b) => (
              <button
                key={b.id}
                onClick={() => runCompile(b.id)}
                disabled={loading}
                className={`px-3 py-1 rounded text-xs font-medium ${
                  result && backend === b.id
                    ? "bg-primary-600/40 text-foreground"
                    : "bg-dark-border text-muted hover:text-foreground"
                }`}
              >
                {b.label}
              </button>
            ))}
          </div>
          {loading && <p className="text-xs text-muted">{t("sigma.compiling")}</p>}
          {error && (
            <p className="text-xs text-red-400 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              {error}
            </p>
          )}
          {result && (
            <div className="relative">
              <pre className="p-3 bg-black/40 rounded text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap break-all">
                {result.query}
              </pre>
              <button
                onClick={copyQuery}
                className="absolute top-2 right-2 p-1.5 bg-dark-border hover:bg-dark-card rounded text-foreground"
                title={t("sigma.copyQuery")}
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
