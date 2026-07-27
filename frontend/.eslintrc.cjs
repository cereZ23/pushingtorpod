/* eslint-env node */
module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  // vue-eslint-parser handles <template>; @typescript-eslint/parser handles <script>.
  parser: "vue-eslint-parser",
  parserOptions: {
    parser: "@typescript-eslint/parser",
    ecmaVersion: "latest",
    sourceType: "module",
  },
  extends: [
    "eslint:recommended",
    // "essential" catches real mistakes (invalid template syntax, unused
    // components, bad v-* usage) without the stylistic strictness of
    // vue3-recommended — keeps the lint signal about bugs, not formatting.
    "plugin:vue/vue3-essential",
    "plugin:@typescript-eslint/recommended",
  ],
  plugins: ["@typescript-eslint"],
  rules: {
    // TypeScript already resolves identifiers; `no-undef` is redundant on TS
    // and false-positives on type-only DOM references (e.g. BlobPart). Off per
    // the @typescript-eslint recommendation — tsc/vue-tsc catch real ones.
    "no-undef": "off",
    // Prettier owns formatting; don't double-report.
    // Real-bug rules stay as errors (from the recommended sets above).
    // `any` is a smell but pre-exists widely — warn, don't block, so the
    // ratchet can enforce errors now and burn down `any` over time.
    "@typescript-eslint/no-explicit-any": "warn",
    // Allow intentionally-unused args/vars prefixed with underscore.
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" },
    ],
  },
  ignorePatterns: [
    "dist/",
    "node_modules/",
    "*.config.ts",
    "*.config.js",
    "env.d.ts",
    "coverage/",
  ],
};
