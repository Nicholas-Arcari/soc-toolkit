import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";
import { registerCommonI18n } from "@sec-toolkit/common/i18n";

import en from "./locales/en.json";
import it from "./locales/it.json";

/**
 * Single-namespace i18n for the SOC toolkit, mirroring the OSINT setup.
 * Browser-language detection with localStorage persistence so the chosen
 * language sticks across reloads. The page bodies are migrated to `t()`
 * incrementally; the sidebar/chrome is the reference implementation.
 */
void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { en: { translation: en }, it: { translation: it } },
    fallbackLng: "en",
    supportedLngs: ["en", "it"],
    interpolation: { escapeValue: false },
    detection: {
      order: ["localStorage", "navigator"],
      caches: ["localStorage"],
      lookupLocalStorage: "soc-toolkit-lang",
    },
  });

// Graft the shared auth (login + gates) translations onto this instance.
registerCommonI18n(i18n);

export default i18n;
