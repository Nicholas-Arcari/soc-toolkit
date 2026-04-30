import { useState, type FormEvent } from "react";
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
  const [value, setValue] = useState("");
  const [type, setType] = useState("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PivotResult | null>(null);
  const [activeTab, setActiveTab] = useState<TabName>("certificates");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;

    const actualType = type === "auto" ? detectType(value) : type;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await pivotOSINT(actualType, value.trim());
      setResult(data);
      setActiveTab(defaultTab(data.target_type));
    } catch {
      setError("Pivot failed. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const tabs = result ? tabsFor(result.target_type, result.pivot) : [];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">IOC Pivot</h1>
        <p className="text-gray-400 mt-2">
          Pivot any indicator across OSINT sources - certificates, passive DNS, WHOIS, ASN, Shodan
        </p>
      </div>

      <form
        onSubmit={handleSubmit}
        className="bg-dark-card rounded-xl border border-dark-border p-6 mb-6"
      >
        <div className="flex gap-3">
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="px-4 py-3 bg-dark-bg border border-dark-border rounded-lg text-sm text-gray-200 focus:outline-none focus:border-primary-500"
          >
            <option value="auto">Auto-detect</option>
            <option value="domain">Domain</option>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
          </select>
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="example.com or 8.8.8.8"
            className="flex-1 px-4 py-3 bg-dark-bg border border-dark-border rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-primary-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !value.trim()}
            className="flex items-center gap-2 px-6 py-3 bg-primary-600 hover:bg-primary-500 disabled:bg-dark-border disabled:text-gray-500 rounded-lg text-sm font-medium transition-colors"
          >
            <Search className="w-4 h-4" />
            {loading ? "Pivoting..." : "Pivot"}
          </button>
        </div>
      </form>

      {loading && (
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500 mx-auto" />
          <p className="text-gray-400 mt-4">Fanning out to OSINT sources...</p>
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
              <span className="text-xs text-gray-400 uppercase tracking-wide">
                {result.target_type}
              </span>
            </div>
            <div className="mt-3 flex flex-wrap gap-4 text-xs text-gray-400">
              {Object.entries(result.summary).map(([k, v]) => (
                <div key={k}>
                  <span className="text-gray-500">{k.replace(/_/g, " ")}:</span>{" "}
                  <span className="text-gray-200 font-mono">{String(v || "-")}</span>
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
                    ? "border-primary-500 text-primary-400"
                    : "border-transparent text-gray-400 hover:text-white"
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
