export interface ClientMetadata {
 [key: string]: string | string[] | number | boolean | Record<string, unknown> | undefined;
 client_name?: string;
 redirect_uris?: string[];
 response_types?: string[];
 grant_types?: string[];
 application_type?: string;
 token_endpoint_auth_method?: string;
}
export interface OIDCClient extends ClientMetadata {
 client_id: string;
 client_id_issued_at: number;
 updated_at: number;
 has_client_secret: boolean;
 client_secret_expires_at?: number;
 protocol_compatible: boolean;
 protocol_incompatibilities?: string[];
}
export interface ClientResult extends OIDCClient { client_secret?: string; }
export interface ClientList { clients: OIDCClient[]; total: number; page: number; pageSize: number; }

export const metadataSections = [
 { title: "Application", fields: [
  ["client_name", "Client name", "text"], ["application_type", "Application type", "application"],
  ["redirect_uris", "Redirect URIs", "list"], ["response_types", "Response types", "list"],
  ["grant_types", "Grant types", "list"],
 ] },
 { title: "Display and contacts", fields: [
  ["contacts", "Contacts", "list"], ["logo_uri", "Logo URI", "url"], ["client_uri", "Client URI", "url"],
  ["policy_uri", "Policy URI", "url"], ["tos_uri", "Terms of service URI", "url"],
 ] },
 { title: "Authentication and subject", fields: [
  ["token_endpoint_auth_method", "Token endpoint authentication method", "auth"],
  ["token_endpoint_auth_signing_alg", "Token endpoint authentication signing algorithm", "text"],
  ["subject_type", "Subject type", "subject"], ["sector_identifier_uri", "Sector identifier URI", "url"],
  ["jwks_uri", "JWKS URI", "url"], ["initiate_login_uri", "Initiate login URI", "url"],
  ["default_max_age", "Default maximum authentication age (seconds)", "number"],
  ["default_acr_values", "Default ACR values", "list"], ["request_uris", "Request URIs", "list"],
 ] },
 { title: "Signing and encryption", fields: [
  ["id_token_signed_response_alg", "ID token signing algorithm", "text"],
  ["id_token_encrypted_response_alg", "ID token encryption algorithm", "text"],
  ["id_token_encrypted_response_enc", "ID token encryption method", "text"],
  ["userinfo_signed_response_alg", "UserInfo signing algorithm", "text"],
  ["userinfo_encrypted_response_alg", "UserInfo encryption algorithm", "text"],
  ["userinfo_encrypted_response_enc", "UserInfo encryption method", "text"],
  ["request_object_signing_alg", "Request object signing algorithm", "text"],
  ["request_object_encryption_alg", "Request object encryption algorithm", "text"],
  ["request_object_encryption_enc", "Request object encryption method", "text"],
 ] },
] as const;
export function clientMetadata(client?: OIDCClient): ClientMetadata {
 if (!client) return { application_type: "web", redirect_uris: [], response_types: ["code"], grant_types: ["authorization_code"], token_endpoint_auth_method: "client_secret_basic", id_token_signed_response_alg: "RS256", require_auth_time: false };
 const allowed = new Set<string>([...metadataSections.flatMap((section) => section.fields.map(([key]) => key)), "jwks", "require_auth_time"]);
 return Object.fromEntries(Object.entries(client).filter(([key]) => allowed.has(key) || key.includes("#"))) as ClientMetadata;
}
