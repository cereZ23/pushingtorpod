const TOKEN_CLASS: Record<"key" | "string" | "number" | "boolean" | "null", string> = {
  key: "text-blue-600 dark:text-blue-400 font-semibold",
  string: "text-green-700 dark:text-green-400",
  number: "text-amber-600 dark:text-amber-400",
  boolean: "text-purple-600 dark:text-purple-400",
  null: "text-gray-400 dark:text-gray-500",
};

const TOKEN_PATTERN =
  /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\btrue\b|\bfalse\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Renders a JSON value as syntax-highlighted HTML (for use with v-html).
 *
 * The value is stringified and HTML-escaped BEFORE any markup is added, so
 * evidence data — which can contain attacker-controlled strings from recon
 * scanning — is never interpreted as HTML. The token regex below only ever
 * matches literal JSON punctuation inside the already-escaped string; the only
 * `<`/`>` characters in the output are the hardcoded <span> tags this
 * function adds itself.
 */
export function highlightJson(value: unknown): string {
  const escaped = escapeHtml(JSON.stringify(value, null, 2) ?? "null");
  return escaped.replace(TOKEN_PATTERN, (match) => {
    let type: keyof typeof TOKEN_CLASS = "number";
    if (match.startsWith('"')) {
      type = match.trimEnd().endsWith(":") ? "key" : "string";
    } else if (match === "true" || match === "false") {
      type = "boolean";
    } else if (match === "null") {
      type = "null";
    }
    return `<span class="${TOKEN_CLASS[type]}">${match}</span>`;
  });
}
