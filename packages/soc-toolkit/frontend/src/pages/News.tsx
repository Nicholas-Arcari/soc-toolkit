import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ExternalLink, RefreshCw } from "lucide-react";
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

  return (
    <div className="max-w-3xl">
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
        <div className="space-y-3">
          {items.map((item) => (
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
    </div>
  );
}
