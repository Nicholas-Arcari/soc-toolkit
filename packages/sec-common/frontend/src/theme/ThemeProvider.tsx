/**
 * Light/dark theme provider shared across the SOC and OSINT frontends.
 *
 * Behaviour lives here; the actual colour values are per-app CSS variables
 * (each frontend's index.css defines :root / .dark). We only toggle the
 * `.dark` class on <html> and persist the user's choice.
 *
 * First choice defaults to the OS preference; once the user toggles, the
 * explicit choice is stored in localStorage and wins on the next visit.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

export type Theme = "light" | "dark";

interface ThemeContextValue {
  theme: Theme;
  toggle: () => void;
  setTheme: (theme: Theme) => void;
}

const STORAGE_KEY = "sectk-theme";

const ThemeContext = createContext<ThemeContextValue | null>(null);

function getInitialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  // Lets native UI (form controls, default scrollbars) follow the theme.
  root.style.colorScheme = theme;
}

// Apply synchronously on first import so there's no light->dark flash before
// React mounts and runs effects.
if (typeof document !== "undefined") {
  applyTheme(getInitialTheme());
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((next: Theme) => {
    window.localStorage.setItem(STORAGE_KEY, next);
    setThemeState(next);
  }, []);

  const toggle = useCallback(() => {
    setThemeState((current) => {
      const next = current === "dark" ? "light" : "dark";
      window.localStorage.setItem(STORAGE_KEY, next);
      return next;
    });
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, toggle, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return ctx;
}

/** Non-throwing variant for components that may render outside the provider. */
export function useOptionalTheme(): ThemeContextValue | null {
  return useContext(ThemeContext);
}
