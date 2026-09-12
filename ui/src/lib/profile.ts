import type { ProfileClaims } from "./api";

// Select only editable claims; never forward identity, authorization, or verification fields.
export function editableClaims(user?: ProfileClaims | null): ProfileClaims {
 const { given_name, family_name, middle_name, nickname, preferred_username, profile, picture, website,
  gender, birthdate, zoneinfo, locale, phone_number, address, custom_attributes } = user ?? {};
 return { given_name, family_name, middle_name, nickname, preferred_username, profile, picture, website,
  gender, birthdate, zoneinfo, locale, phone_number, address, custom_attributes };
}
export function parseCustomAttributes(text: string): Record<string, unknown> {
 const parsed: unknown = JSON.parse(text);
 if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Custom attributes must be a JSON object.");
 return parsed as Record<string, unknown>;
}
