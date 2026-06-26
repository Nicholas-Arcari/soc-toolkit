import { NavLink } from "react-router-dom";
import {
  Languages,
  LogOut,
  Shield,
  Sun,
  Moon,
  Settings as SettingsIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { trialDaysLeft, useOptionalAuth } from "@sec-toolkit/common/auth";
import { useOptionalTheme } from "@sec-toolkit/common/theme";
import { navItems } from "../../lib/modules";
import Avatar from "./Avatar";
import XpBar from "./XpBar";
import PageHelp from "./PageHelp";

export default function Sidebar() {
  const { t, i18n } = useTranslation();
  const auth = useOptionalAuth();
  const state = auth?.state ?? null;
  const logout = auth?.logout;
  const theme = useOptionalTheme();
  const trialLeft = state ? trialDaysLeft(state.user) : null;
  const lang = i18n.resolvedLanguage === "it" ? "it" : "en";

  return (
    <aside className="w-64 bg-card border-r border-border flex flex-col">
      <div className="p-6 border-b border-border flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-emerald-400" />
          <div>
            <h1 className="text-lg font-bold text-foreground">SOC Toolkit</h1>
            <p className="text-xs text-muted">{t("sidebar.version")}</p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <PageHelp />
          <NavLink
            to="/settings"
            aria-label={t("sidebar.settings")}
            title={t("sidebar.settingsTitle")}
            className={({ isActive }) =>
              `p-2 rounded-lg transition-colors ${
                isActive
                  ? "text-foreground bg-foreground/5"
                  : "text-muted hover:text-foreground hover:bg-foreground/5"
              }`
            }
          >
            <SettingsIcon className="w-4 h-4" />
          </NavLink>
          <button
            type="button"
            onClick={() => void i18n.changeLanguage(lang === "it" ? "en" : "it")}
            aria-label={t("sidebar.language")}
            title={t("sidebar.language")}
            className="px-2 py-2 rounded-lg text-xs font-semibold text-muted hover:text-foreground hover:bg-foreground/5 transition-colors inline-flex items-center gap-1"
          >
            <Languages className="w-4 h-4" />
            {lang.toUpperCase()}
          </button>
          {theme && (
            <button
              type="button"
              onClick={theme.toggle}
              aria-label="Toggle light/dark theme"
              title={
                theme.theme === "dark"
                  ? t("sidebar.themeToLight")
                  : t("sidebar.themeToDark")
              }
              className="p-2 rounded-lg text-muted hover:text-foreground hover:bg-foreground/5 transition-colors"
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

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map(({ path, label, icon: Icon, color, tint }) => (
          <NavLink
            key={path}
            to={path}
            end={path === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                isActive
                  ? `${tint} text-foreground`
                  : "text-muted hover:bg-foreground/5 hover:text-foreground"
              }`
            }
          >
            <Icon className={`w-5 h-5 shrink-0 ${color}`} />
            <span className="text-sm font-medium">
              {t(`nav.${path}`, label)}
            </span>
          </NavLink>
        ))}
      </nav>

      {state && (
        <div className="p-4 border-t border-border space-y-2">
          <NavLink
            to="/profile"
            className={({ isActive }) =>
              `flex items-center gap-2.5 p-1.5 rounded-lg transition-colors ${
                isActive ? "bg-foreground/5" : "hover:bg-foreground/5"
              }`
            }
          >
            <Avatar
              username={state.user.username}
              avatar={state.user.avatar}
              size={32}
            />
            <div className="min-w-0">
              <p
                className="text-sm font-medium text-foreground truncate"
                title={state.user.username}
              >
                {state.user.username}
              </p>
              <p className="text-xs text-muted">{t("sidebar.viewProfile")}</p>
            </div>
          </NavLink>
          <XpBar user={state.user} className="px-1 pt-1" />
          {trialLeft !== null && (
            <div className="px-1">
              <span className="inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
                {t("sidebar.trial", { days: trialLeft })}
              </span>
            </div>
          )}
          {logout && (
            <button
              type="button"
              onClick={logout}
              className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-muted hover:bg-foreground/5 hover:text-foreground text-sm transition-colors"
            >
              <LogOut className="w-4 h-4" />
              {t("sidebar.signOut")}
            </button>
          )}
        </div>
      )}

      <div className="p-4 border-t border-border space-y-1.5 text-center">
        <NavLink
          to="/contact"
          className={({ isActive }) =>
            `block text-xs transition-colors ${
              isActive ? "text-foreground" : "text-muted hover:text-foreground"
            }`
          }
        >
          {t("sidebar.contact")}
        </NavLink>
        <p className="text-xs text-muted">Nicholas Arcari</p>
      </div>
    </aside>
  );
}
