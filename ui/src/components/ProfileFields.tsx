import type { ProfileClaims } from "../lib/api";

const fields = [
 ["given_name", "Given name"], ["family_name", "Family name"], ["middle_name", "Middle name"],
 ["nickname", "Nickname"], ["preferred_username", "Preferred username"],
 ["profile", "Profile URL"], ["picture", "Picture URL"], ["website", "Website"],
 ["gender", "Gender"], ["birthdate", "Birthdate"], ["zoneinfo", "Time zone"], ["locale", "Locale"],
 ["phone_number", "Phone number"],
] as const;
const addressFields = [
 ["formatted", "Formatted address"], ["street_address", "Street address"], ["locality", "City / locality"],
 ["region", "State / region"], ["postal_code", "Postal code"], ["country", "Country"],
] as const;

export default function ProfileFields({ value, onChange, custom, onCustomChange }: {
 value: ProfileClaims; onChange: (value: ProfileClaims) => void; custom: string; onCustomChange: (value: string) => void;
}) {
 return <>
  <fieldset className="flex flex-col gap-4">
   <legend className="mb-3 font-semibold">OpenID Connect attributes</legend>
   <div className="grid gap-4 md:grid-cols-2">
    {fields.map(([key, label]) => <label key={key} className="flex flex-col gap-1.5 text-sm font-medium">{label}
     <input className="input" type={["profile", "picture", "website"].includes(key) ? "url" : "text"} maxLength={2048}
      placeholder={key === "birthdate" ? "YYYY-MM-DD or YYYY" : key === "zoneinfo" ? "America/Los_Angeles" : key === "locale" ? "en-US" : undefined}
      value={value[key] ?? ""} onChange={(e) => onChange({ ...value, [key]: e.target.value })} />
    </label>)}
   </div>
  </fieldset>
  <fieldset><legend className="mb-3 font-semibold">Address</legend><div className="grid gap-4 md:grid-cols-2">
   {addressFields.map(([key, label]) => <label key={key} className="flex flex-col gap-1.5 text-sm font-medium">{label}
    <input className="input" maxLength={2048} value={value.address?.[key] ?? ""} onChange={(e) => onChange({ ...value, address: { ...value.address, [key]: e.target.value } })} />
   </label>)}
  </div></fieldset>
  <label className="flex flex-col gap-1.5 text-sm font-medium">Custom attributes (JSON)
   <textarea className="input min-h-32 font-mono" value={custom} maxLength={16384} onChange={(e) => onCustomChange(e.target.value)} spellCheck={false} />
   <span className="text-xs font-normal text-ink-faint">A JSON object with up to 50 custom attributes. Values may be text, numbers, booleans, lists, or objects. These attributes do not grant application permissions.</span>
  </label>
 </>;
}
