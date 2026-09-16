export function safeRedirect(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || [...value].some((char) => char.charCodeAt(0) <= 32) || value.split("?")[0] === "/login") return "/";
  return value;
}

// A thin, mockable seam around a full browser navigation (as opposed to a
// client-side router transition) — used to follow OIDC redirect targets,
// which are frequently cross-origin. Kept as its own function so tests can
// intercept it instead of stubbing jsdom's unsupported window.location
// navigation.
export function navigateExternal(url: string) {
  window.location.href = url;
}
