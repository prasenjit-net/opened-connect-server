// Keep existing preferences when upgrading from the misspelled project name.
export function readPreference(key: string): string | null {
  const saved = localStorage.getItem(key);
  if (saved !== null) return saved;

  const legacyKey = key.replace("openid-connect-server-", "opened-connect-server-");
  const legacy = localStorage.getItem(legacyKey);
  if (legacy !== null) {
    localStorage.setItem(key, legacy);
    localStorage.removeItem(legacyKey);
  }
  return legacy;
}
