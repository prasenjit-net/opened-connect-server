import { describe, expect, it } from "vitest";
import { readPreference } from "./preferences";

describe("preference name migration", () => {
  it.each([
    ["theme", "dark"],
    ["sidebar", "collapsed"],
  ])("preserves the saved %s preference", (name, value) => {
    const legacyKey = `opened-connect-server-${name}`;
    const key = `openid-connect-server-${name}`;
    localStorage.setItem(legacyKey, value);

    expect(readPreference(key)).toBe(value);
    expect(localStorage.getItem(key)).toBe(value);
    expect(localStorage.getItem(legacyKey)).toBeNull();
  });

  it("prefers the new key when both names exist", () => {
    localStorage.setItem("opened-connect-server-theme", "dark");
    localStorage.setItem("openid-connect-server-theme", "light");
    expect(readPreference("openid-connect-server-theme")).toBe("light");
  });

  it("leaves an unset preference unset", () => {
    expect(readPreference("openid-connect-server-theme")).toBeNull();
    expect(localStorage.getItem("openid-connect-server-theme")).toBeNull();
  });
});
