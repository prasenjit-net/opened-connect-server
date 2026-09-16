import { useId } from "react";

// Keep rows editable until submission: removing one item never rewrites the
// other entries, and blank optional rows are discarded by the parent form.
export default function ListField({ label, value, onChange, required = false, type = "text", placeholder }: {
 label: string; value: string; onChange: (value: string) => void; required?: boolean; type?: "text" | "url" | "email"; placeholder?: string;
}) {
 const id = useId(); const rows = value.split("\n");
 const itemLabel = ({ "Redirect URIs": "redirect URI", "Request URIs": "request URI", "Contacts": "contact", "Default ACR values": "ACR value" } as Record<string, string>)[label] ?? "value";
 return <fieldset className="min-w-0 rounded-lg border border-line p-3">
  <legend className="px-1 text-sm font-medium">{label}</legend>
  <div className="flex flex-col gap-2">{rows.map((row, index) => <div key={index} className="flex min-w-0 items-center gap-2">
   <label htmlFor={`${id}-${index}`} className="sr-only">{label}{index > 0 ? ` ${index + 1}` : ""}</label>
   <input id={`${id}-${index}`} className="input min-w-0 flex-1" type={type} maxLength={2048} placeholder={placeholder} required={required && index === 0 && !rows.some(item => item.trim())} value={row} onChange={e => onChange(rows.map((item, i) => i === index ? e.target.value : item).join("\n"))} />
   <button type="button" className="btn btn-ghost btn-sm shrink-0" aria-label={`Remove ${itemLabel} ${index + 1}`} onClick={() => onChange(rows.filter((_, i) => i !== index).join("\n"))}>Remove</button>
  </div>)}</div>
  <button type="button" className="btn btn-secondary btn-sm mt-3" disabled={rows.length >= 100} onClick={() => onChange(`${value}\n`)}>Add {itemLabel}</button>
 </fieldset>;
}
