import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import it from "./locales/it.json";

/**
 * Single-namespace setup - the app is small enough that one bundle per
 * language beats the cognitive cost of slicing translations by page.
 * Browser-language detection with localStorage persistence so toggling
 * sticks across reloads without a round-trip to the backend.
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
      lookupLocalStorage: "osint-toolkit-lang",
    },
  });

export default i18n;
