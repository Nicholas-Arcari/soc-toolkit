/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Semantic surface/text tokens, theme-aware via CSS variables
        // (defined in src/index.css for :root [light] and .dark). RGB
        // triplets so Tailwind's <alpha-value> works: bg-card, text-foreground,
        // border-border, text-muted, bg-foreground/5, etc.
        background: "rgb(var(--bg) / <alpha-value>)",
        foreground: "rgb(var(--fg) / <alpha-value>)",
        card: "rgb(var(--card) / <alpha-value>)",
        border: "rgb(var(--border) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        // Legacy aliases kept theme-aware so the not-yet-migrated inner pages
        // (step 1b) still respond to light/dark with no edit. Removed once the
        // pages move to the semantic tokens above.
        dark: {
          bg: "rgb(var(--bg) / <alpha-value>)",
          card: "rgb(var(--card) / <alpha-value>)",
          border: "rgb(var(--border) / <alpha-value>)",
        },
        // Neutral accent ramp replacing the old blue `primary` (buttons, focus
        // rings, links). Colour now comes from per-category icons + severity.
        primary: {
          50: "#fafafa",
          100: "#f4f4f5",
          200: "#e4e4e7",
          300: "#d4d4d8",
          400: "#a1a1aa",
          500: "#71717a",
          600: "#52525b",
          700: "#3f3f46",
          800: "#27272a",
          900: "#18181b",
          950: "#09090b",
        },
      },
    },
  },
  plugins: [],
};
