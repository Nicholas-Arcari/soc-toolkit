// Shared ESLint flat config for every frontend workspace in this
// monorepo. Exported as a factory so individual apps can tack on
// app-specific overrides (globals, ignores) without forking the baseline.
//
// Usage (per-app eslint.config.js):
//
//   import { createBaseConfig } from "@sec-toolkit/common/eslint.config";
//   export default createBaseConfig();
//
// To extend, pass an array of extra flat-config objects - they are
// concatenated after the shared rules so they win on conflict.

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import jsxA11y from "eslint-plugin-jsx-a11y";
import globals from "globals";

export function createBaseConfig(extra = []) {
  return [
    {
      // Repo-wide ignores. `dist` is the Vite build output, `coverage`
      // is from vitest --coverage runs.
      ignores: ["dist/**", "coverage/**", "node_modules/**", "*.config.js", "*.config.ts"],
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
      files: ["**/*.{ts,tsx}"],
      languageOptions: {
        ecmaVersion: 2022,
        sourceType: "module",
        globals: {
          ...globals.browser,
          ...globals.es2022,
        },
      },
      plugins: {
        "react-hooks": reactHooks,
        "react-refresh": reactRefresh,
        "jsx-a11y": jsxA11y,
      },
      rules: {
        ...reactHooks.configs.recommended.rules,
        ...jsxA11y.configs.recommended.rules,
        "react-refresh/only-export-components": [
          "warn",
          { allowConstantExport: true },
        ],
        // Allow underscore-prefixed unused args (common in event handlers
        // where React passes args the component doesn't need).
        "@typescript-eslint/no-unused-vars": [
          "error",
          { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
        ],
        // Practical for React: tests and stubs use `any` in controlled
        // contexts; enforce as warn so it gets flagged but doesn't block.
        "@typescript-eslint/no-explicit-any": "warn",
      },
    },
    {
      // Test files are allowed to be loose - they deal with mocks and
      // narrow assertion shapes that don't always match production types.
      files: [
        "**/*.test.{ts,tsx}",
        "**/__tests__/**/*.{ts,tsx}",
        "**/test/**/*.{ts,tsx}",
      ],
      languageOptions: {
        globals: {
          ...globals.browser,
          ...globals.node,
        },
      },
      rules: {
        "@typescript-eslint/no-explicit-any": "off",
        "@typescript-eslint/no-non-null-assertion": "off",
      },
    },
    ...extra,
  ];
}
