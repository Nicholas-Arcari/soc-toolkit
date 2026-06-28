import { useEffect, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { pivotOSINT, type PivotResult } from "../api/client";
import { TabContent, defaultTab, tabsFor, type TabName } from "../components/pivot/PivotViews";

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

function detectType(value: string): string {
  const trimmed = value.trim();
  if (IPV4.test(trimmed)) return "ipv4";
  if (trimmed.includes(":") && IPV6.test(trimmed)) return "ipv6";
  return "domain";
}

export default function IOCPivot() {
  const { t } = useTranslation();
  const [value, setValue] = useState("");
  const [type, setType] = useState("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PivotResult | null>(null);
  const [activeTab, setActiveTab] = useState<TabName>("certificates");
  const [searchParams] = useSearchParams();
  const autoRan = useRef(false);

  async function runPivot(indicator: string, typeChoice: string) {
    const trimmed = indicator.trim();
    if (!trimmed) return;
    const actualType = typeChoice === "auto" ? detectType(trimmed) : typeChoice;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await pivotOSINT(actualType, trimmed);
      setResult(data);
      setActiveTab(defaultTab(data.target_type));
    } catch {
      setError(t("iocPivot.error"));
    } finally {
      setLoading(false);
    }
  }

  // Deep-link: /ioc-pivot?q=<indicator> pre-fills + auto-runs once, so the
  // other analyzers can pivot an indicator straight into here.
  useEffect(() => {
    if (autoRan.current) return;
    const q = searchParams.get("q");
    if (q) {
      autoRan.current = true;
      setValue(q);
      void runPivot(q, "auto");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runPivot(value, type);
  };

  const tabs = result ? tabsFor(result.target_type, result.pivot) : [];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">{t("iocPivot.title")}</h1>
        <p className="text-muted mt-2">{t("iocPivot.subtitle")}</p>
      </div>

      <form
        onSubmit={handleSubmit}
        className="bg-dark-card rounded-xl border border-dark-border p-6 mb-6"
      >
        <div className="flex gap-3">
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="px-4 py-3 bg-dark-bg border border-dark-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary-500"
          >
            <option value="auto">{t("iocPivot.autoDetect")}</option>
            <option value="domain">{t("iocPivot.domain")}</option>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
          </select>
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={t("iocPivot.placeholder")}
            className="flex-1 px-4 py-3 bg-dark-bg border border-dark-border rounded-lg text-sm text-foreground placeholder-muted focus:outline-none focus:border-primary-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !value.trim()}
            className="flex items-center gap-2 px-6 py-3 bg-primary-600 hover:bg-primary-500 disabled:bg-dark-border disabled:text-muted rounded-lg text-sm font-medium transition-colors"
          >
            <Search className="w-4 h-4" />
            {loading ? t("iocPivot.pivoting") : t("iocPivot.pivot")}
          </button>
        </div>
      </form>

      {loading && (
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-muted mt-4">{t("iocPivot.fanningOut")}</p>
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-400">{error}</div>
      )}

      {result?.error && (
        <div className="bg-yellow-900/20 border border-yellow-700 rounded-xl p-4 text-yellow-400">
          {result.error}
        </div>
      )}

      {result && !result.error && !loading && (
        <div className="space-y-6">
          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <div className="flex items-baseline justify-between">
              <h2 className="text-xl font-semibold font-mono">{result.target}</h2>
              <span className="text-xs text-muted uppercase tracking-wide">
                {result.target_type}
              </span>
            </div>
            <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted">
              {Object.entries(result.summary).map(([k, v]) => (
                <div key={k}>
                  <span className="text-muted">{k.replace(/_/g, " ")}:</span>{" "}
                  <span className="text-foreground font-mono">{String(v || "-")}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-2 border-b border-dark-border">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                  activeTab === tab.key
                    ? "border-primary-500 text-foreground"
                    : "border-transparent text-muted hover:text-foreground"
                }`}
              >
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className="ml-2 px-2 py-0.5 bg-dark-border rounded text-xs">{tab.count}</span>
                )}
              </button>
            ))}
          </div>

          <div className="bg-dark-card rounded-xl border border-dark-border p-6">
            <TabContent tab={activeTab} pivot={result.pivot} />
          </div>
        </div>
      )}
    </div>
  );
}
