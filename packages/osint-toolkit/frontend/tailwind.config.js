/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Theme-aware semantic tokens via CSS variables (src/index.css:
        // :root = light, .dark = dark). RGB triplets so <alpha-value> works:
        // bg-card, text-foreground, border-border, text-muted, bg-foreground/5.
        background: "rgb(var(--bg) / <alpha-value>)",
        foreground: "rgb(var(--fg) / <alpha-value>)",
        card: "rgb(var(--card) / <alpha-value>)",
        border: "rgb(var(--border) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        // Legacy aliases kept theme-aware so existing bg-dark-*/border-dark-*
        // usages respond to light/dark with no edit.
        dark: {
          bg: "rgb(var(--bg) / <alpha-value>)",
          card: "rgb(var(--card) / <alpha-value>)",
          border: "rgb(var(--border) / <alpha-value>)",
        },
        // OSINT's teal accent (buttons, links, focus) over the neutral base.
        primary: {
          50: "#f0fdfa",
          100: "#ccfbf1",
          200: "#99f6e4",
          300: "#5eead4",
          400: "#2dd4bf",
          500: "#14b8a6",
          600: "#0d9488",
          700: "#0f766e",
          800: "#115e59",
          900: "#134e4a",
          950: "#042f2e",
        },
      },
    },
  },
  plugins: [],
};
