import "@testing-library/jest-dom/vitest";
import "../i18n";

// jsdom doesn't implement matchMedia; the shared ThemeProvider reads it to
// pick the initial light/dark preference, so stub it for component tests.
if (!window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
