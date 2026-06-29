import { NavLink } from "react-router-dom";
import {
  ArrowLeftRight,
  LayoutDashboard,
  LogOut,
  Target as TargetIcon,
  Crosshair,
  Search,
  Languages,
  Sun,
  Moon,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { useOptionalAuth } from "@sec-toolkit/common/auth";
import { useOptionalTheme } from "@sec-toolkit/common/theme";

const LANGS = ["en", "it"] as const;

export default function Sidebar() {
  const { t, i18n } = useTranslation();
  const auth = useOptionalAuth();
  const theme = useOptionalTheme();
  const state = auth?.state ?? null;
  const logout = auth?.logout;

  const navItems = [
    { path: "/", label: t("sidebar.nav.dashboard"), icon: LayoutDashboard, end: true },
    { path: "/targets", label: t("sidebar.nav.targets"), icon: TargetIcon, end: false },
    { path: "/investigate", label: t("sidebar.nav.investigate"), icon: Search, end: false },
  ];

  const currentLang: (typeof LANGS)[number] = LANGS.includes(
    i18n.resolvedLanguage as (typeof LANGS)[number],
  )
    ? (i18n.resolvedLanguage as (typeof LANGS)[number])
    : "en";

  return (
    <aside className="w-64 bg-dark-card border-r border-dark-border flex flex-col">
      <div className="p-6 border-b border-dark-border">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Crosshair className="w-8 h-8 text-primary-500" />
            <div>
              <h1 className="text-lg font-bold">{t("sidebar.appName")}</h1>
              <p className="text-xs text-muted">{t("sidebar.version")}</p>
            </div>
          </div>
          {theme && (
            <button
              type="button"
              onClick={theme.toggle}
              aria-label="Toggle light/dark theme"
              title={
                theme.theme === "dark" ? "Switch to light" : "Switch to dark"
              }
              className="p-2 rounded-lg text-muted hover:bg-dark-border/50 hover:text-foreground"
            >
              {theme.theme === "dark" ? (
                <Sun className="w-4 h-4" />
              ) : (
                <Moon className="w-4 h-4" />
              )}
            </button>
          )}
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map(({ path, label, icon: Icon, end }) => (
          <NavLink
            key={path}
            to={path}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive
                  ? "bg-primary-600/20 text-primary-400"
                  : "text-muted hover:bg-dark-border/50 hover:text-foreground"
              }`
            }
          >
            <Icon className="w-5 h-5" />
            <span className="text-sm font-medium">{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Jump to the companion SOC app. Points at the custom domain set up
          via the local reverse proxy + /etc/hosts; change to http://localhost:3000 for a
          plain-port dev setup. */}
      <div className="px-4 pb-2">
        <a
          href="https://soctoolkit/"
          title="SOC Toolkit"
          className="flex items-center gap-3 px-4 py-3 rounded-lg text-muted hover:bg-dark-border/50 hover:text-foreground transition-colors"
        >
          <ArrowLeftRight className="w-5 h-5" />
          <span className="text-sm font-medium">SOC Toolkit</span>
        </a>
      </div>

      <div className="p-4 border-t border-dark-border space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs text-muted">
            <Languages className="w-3.5 h-3.5" />
            {t("sidebar.language")}
          </div>
          <div className="flex gap-1" role="group" aria-label={t("sidebar.language")}>
            {LANGS.map((lng) => (
              <button
                key={lng}
                type="button"
                onClick={() => void i18n.changeLanguage(lng)}
                aria-pressed={currentLang === lng}
                className={`text-xs px-2 py-0.5 rounded font-mono uppercase ${
                  currentLang === lng
                    ? "bg-primary-600/20 text-primary-400"
                    : "bg-dark-border text-muted hover:text-foreground"
                }`}
              >
                {lng}
              </button>
            ))}
          </div>
        </div>
        {state && logout && (
          <div className="space-y-2">
            <div className="text-xs text-muted truncate" title={state.user.username}>
              {state.user.username}
            </div>
            <button
              type="button"
              onClick={logout}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-muted hover:bg-dark-border/50 hover:text-foreground text-sm"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </div>
        )}
        <p className="text-xs text-muted text-center">Nicholas Arcari</p>
      </div>
    </aside>
  );
}
