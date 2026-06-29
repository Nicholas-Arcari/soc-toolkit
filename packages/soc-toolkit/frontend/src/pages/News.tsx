import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ExternalLink, RefreshCw, Search } from "lucide-react";
import { fetchNews, type NewsItem } from "../api/client";

function timeAgo(iso: string | null, t: TFunction): string {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 60) return t("news.minutesAgo", { n: mins });
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return t("news.hoursAgo", { n: hrs });
  return t("news.daysAgo", { n: Math.round(hrs / 24) });
}

export default function News() {
  const { t } = useTranslation();
  const [items, setItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("all");

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchNews()
      .then((r) => setItems(r.items))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Source list for the filter dropdown, derived from whatever loaded.
  const sources = useMemo(() => {
    const set = new Set(items.map((i) => i.source).filter(Boolean));
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [items]);

  // Client-side filter: free-text matches title/summary/source (title +
  // topic), the dropdown narrows by source (website).
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter((item) => {
      if (source !== "all" && item.source !== source) return false;
      if (!q) return true;
      return (
        item.title.toLowerCase().includes(q) ||
        item.summary.toLowerCase().includes(q) ||
        item.source.toLowerCase().includes(q)
      );
    });
  }, [items, query, source]);

  return (
    <div>
      <div className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-foreground">
            {t("news.title")}
          </h1>
          <p className="text-muted mt-2">{t("news.subtitle")}</p>
        </div>
        <button
          type="button"
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 text-sm px-3 py-2 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          {t("news.refresh")}
        </button>
      </div>

      {error ? (
        <div className="bg-card border border-border rounded-xl p-6 text-muted">
          {t("news.error")}
        </div>
      ) : loading && items.length === 0 ? (
        <p className="text-muted">{t("news.loading")}</p>
      ) : items.length === 0 ? (
        <p className="text-muted">{t("news.empty")}</p>
      ) : (
        <>
          <div className="mb-5 flex flex-col gap-3 sm:flex-row">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t("news.searchPlaceholder")}
                className="w-full bg-card border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              aria-label={t("news.allSources")}
              className="bg-card border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary-500 sm:w-56"
            >
              <option value="all">{t("news.allSources")}</option>
              {sources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          {filtered.length === 0 ? (
            <p className="text-muted">{t("news.noMatch")}</p>
          ) : (
            <div className="space-y-3">
              {filtered.map((item) => (
                <a
                  key={item.link}
                  href={item.link}
                  target="_blank"
                  rel="noreferrer"
                  className="block bg-card border border-border rounded-xl p-4 hover:border-foreground/20 transition-colors group"
                >
                  <div className="flex items-center gap-2 text-xs text-muted mb-1.5">
                    <span className="px-2 py-0.5 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/30">
                      {item.source}
                    </span>
                    {item.published && <span>{timeAgo(item.published, t)}</span>}
                  </div>
                  <h2 className="text-sm font-semibold text-foreground inline-flex items-start gap-1 group-hover:underline">
                    {item.title}
                    <ExternalLink className="w-3.5 h-3.5 mt-0.5 shrink-0 text-muted" />
                  </h2>
                  {item.summary && (
                    <p className="text-sm text-muted mt-1.5 line-clamp-2">
                      {item.summary}
                    </p>
                  )}
                </a>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
