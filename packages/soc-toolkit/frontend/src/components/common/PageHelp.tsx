import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { HelpCircle, X } from "lucide-react";
import { PAGE_HELP } from "../../lib/help";
import { navItems } from "../../lib/modules";

// A "?" button (lives in the sidebar header) that opens contextual help for
// the current route. On the homepage it also lists every page and what it
// does, reusing the module metadata so there's a single source of truth.
export default function PageHelp() {
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);

  const entry = PAGE_HELP[pathname] ?? PAGE_HELP["/"];
  const isHome = pathname === "/";
  const pages = navItems.filter((n) => n.path !== "/");

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Help"
        title="What is this page?"
        className="p-2 rounded-lg text-muted hover:text-foreground hover:bg-foreground/5 transition-colors"
      >
        <HelpCircle className="w-4 h-4" />
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
          <button
            type="button"
            aria-label="Close help"
            onClick={() => setOpen(false)}
            className="absolute inset-0 bg-black/50"
          />
          <div className="relative w-full max-w-lg bg-card border border-border rounded-2xl p-6 shadow-2xl max-h-[80vh] overflow-y-auto">
            <div className="flex items-start justify-between gap-4 mb-3">
              <h2 className="text-lg font-semibold text-foreground">
                {entry.title}
              </h2>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close"
                className="p-1 text-muted hover:text-foreground shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-sm text-muted">{entry.summary}</p>

            {entry.steps && entry.steps.length > 0 && (
              <ol className="mt-4 space-y-2 text-sm text-muted list-decimal list-inside">
                {entry.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            )}

            {isHome && (
              <div className="mt-5 border-t border-border pt-4">
                <p className="text-xs font-medium text-muted mb-2">The pages</p>
                <ul className="space-y-1">
                  {pages.map(({ path, label, description, icon: Icon, color }) => (
                    <li key={path}>
                      <Link
                        to={path}
                        onClick={() => setOpen(false)}
                        className="flex items-start gap-2.5 rounded-lg p-2 hover:bg-foreground/5 transition-colors"
                      >
                        <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${color}`} />
                        <span>
                          <span className="text-sm font-medium text-foreground">
                            {label}
                          </span>
                          <span className="block text-xs text-muted">
                            {description}
                          </span>
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
