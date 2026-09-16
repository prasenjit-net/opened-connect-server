import { useId } from "react";
import type { ProfileClaims } from "../lib/api";

const supportedTimeZones = (Intl as typeof Intl & { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone") ?? ["America/Los_Angeles", "America/New_York", "Europe/London", "Europe/Paris", "Asia/Kolkata", "Asia/Tokyo", "Australia/Sydney"];
const suggestions: Record<string, string[]> = {
 zoneinfo: ["UTC", ...supportedTimeZones],
 locale: ["en-US", "en-GB", "fr-FR", "de-DE", "es-ES", "pt-BR", "hi-IN", "ja-JP", "zh-CN", "ar-SA"],
 gender: ["female", "male", "non-binary", "prefer not to say"],
};
const groups = [
 { title: "Personal identity", description: "Names and personal details shared with connected applications when authorized.", fields: [
  ["given_name", "Given name"], ["family_name", "Family name"], ["middle_name", "Middle name"],
  ["nickname", "Nickname"], ["preferred_username", "Preferred username"], ["gender", "Gender"], ["birthdate", "Birthdate"],
 ] },
 { title: "Contact and public profile", description: "Phone number, profile image, and links that describe this person.", fields: [
  ["phone_number", "Phone number"], ["picture", "Picture URL"], ["profile", "Profile URL"], ["website", "Website"],
 ] },
 { title: "Language and region", description: "Preferences for language and local time.", fields: [["locale", "Locale"], ["zoneinfo", "Time zone"]] },
] as const;
const addressFields = [
 ["formatted", "Formatted address"], ["street_address", "Street address"], ["locality", "City / locality"],
 ["region", "State / region"], ["postal_code", "Postal code"], ["country", "Country"],
] as const;

export default function ProfileFields({ value, onChange, custom, onCustomChange }: {
 value: ProfileClaims; onChange: (value: ProfileClaims) => void; custom: string; onCustomChange: (value: string) => void;
}) {
 const id = useId();
 return <>
  {groups.map(group => <fieldset key={group.title} className="form-section">
   <legend className="form-section-title">{group.title}</legend>
   <p className="form-section-description">{group.description}</p>
   <div className="grid min-w-0 gap-4 md:grid-cols-2 xl:grid-cols-3">
    {group.fields.map(([key, label]) => <label key={key} className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">{label}
     <input className="input" type={["profile", "picture", "website"].includes(key) ? "url" : key === "phone_number" ? "tel" : "text"} list={suggestions[key] ? `${id}-${key}` : undefined} maxLength={2048}
      placeholder={key === "birthdate" ? "YYYY-MM-DD or YYYY" : key === "zoneinfo" ? "America/Los_Angeles" : key === "locale" ? "en-US" : undefined}
      value={value[key] ?? ""} onChange={(e) => onChange({ ...value, [key]: e.target.value })} />
     {suggestions[key] && <datalist id={`${id}-${key}`}>{suggestions[key].map(option => <option key={option} value={option} />)}</datalist>}
     {key === "birthdate" && <span className="text-xs font-normal text-ink-faint">Full date or year only; use 0000 for an unspecified year.</span>}
     {suggestions[key] && <span className="text-xs font-normal text-ink-faint">Choose a suggestion or enter your own value.</span>}
    </label>)}
   </div>
  </fieldset>)}
  <fieldset className="form-section"><legend className="form-section-title">Postal address</legend><p className="form-section-description">Optional mailing address. Use individual fields for structured data and formatted address for display.</p><div className="grid min-w-0 gap-4 md:grid-cols-2 xl:grid-cols-3">
   {addressFields.map(([key, label]) => <label key={key} className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">{label}
    {key === "formatted" || key === "street_address" ? <textarea className="input min-h-24" maxLength={2048} value={value.address?.[key] ?? ""} onChange={e => onChange({ ...value, address: { ...value.address, [key]: e.target.value } })} /> : <input className="input" maxLength={2048} value={value.address?.[key] ?? ""} onChange={(e) => onChange({ ...value, address: { ...value.address, [key]: e.target.value } })} />}
   </label>)}
  </div></fieldset>
  <fieldset className="form-section"><legend className="form-section-title">Custom claims</legend><p className="form-section-description">Application-specific attributes beyond the standard profile fields.</p>
  <label className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">Custom attributes (JSON)
   <textarea className="input min-h-32 font-mono" value={custom} maxLength={16384} onChange={(e) => onCustomChange(e.target.value)} spellCheck={false} />
   <span className="text-xs font-normal text-ink-faint">A JSON object with up to 50 custom attributes. Values may be text, numbers, booleans, lists, or objects. These attributes do not grant application permissions.</span>
  </label></fieldset>
 </>;
}
