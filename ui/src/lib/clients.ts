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
 { title: "Application and redirects", description: "Start here: identify the application and set its allowed sign-in callback URLs.", fields: [
  ["client_name", "Client name", "text"], ["application_type", "Application type", "application"],
  ["redirect_uris", "Redirect URIs", "list"],
 ] },
 { title: "Authorization flow", description: "Choose how this application requests authorization and receives tokens. Authorization code is the supported flow.", fields: [
  ["response_types", "Response types", "list"], ["grant_types", "Grant types", "list"],
 ] },
 { title: "Client authentication and keys", description: "Control how the application authenticates at the token endpoint. Public keys can be provided by URI or inline below.", fields: [
  ["token_endpoint_auth_method", "Token endpoint authentication method", "auth"],
  ["token_endpoint_auth_signing_alg", "Token endpoint authentication signing algorithm", "text"],
  ["jwks_uri", "JWKS URI", "url"],
 ] },
 { title: "Branding and contacts", description: "Help users recognize the application and find its website, policies, and support contacts.", fields: [
  ["logo_uri", "Logo URI", "url"], ["client_uri", "Client URI", "url"],
  ["policy_uri", "Policy URI", "url"], ["tos_uri", "Terms of service URI", "url"], ["contacts", "Contacts", "list"],
 ] },
 { title: "Login requirements", description: "Optional controls for login freshness, authentication context, and application-initiated sign-in.", fields: [
  ["default_max_age", "Default maximum authentication age (seconds)", "number"],
  ["default_acr_values", "Default ACR values", "list"], ["initiate_login_uri", "Initiate login URI", "url"],
 ] },
 { title: "Subject privacy", description: "Configure how user identifiers are shared with this application.", fields: [
  ["subject_type", "Subject type", "subject"], ["sector_identifier_uri", "Sector identifier URI", "url"],
 ] },
 { title: "ID token protection", description: "The provider currently issues RS256 ID tokens. Other signing algorithms and encryption requirements can be stored but make the client incompatible.", fields: [
  ["id_token_signed_response_alg", "ID token signing algorithm", "text"],
  ["id_token_encrypted_response_alg", "ID token encryption algorithm", "text"],
  ["id_token_encrypted_response_enc", "ID token encryption method", "text"],
 ] },
 { title: "UserInfo protection", description: "UserInfo currently returns unsigned JSON. Signing or encryption requirements make the client incompatible.", fields: [
  ["userinfo_signed_response_alg", "UserInfo signing algorithm", "text"],
  ["userinfo_encrypted_response_alg", "UserInfo encryption algorithm", "text"],
  ["userinfo_encrypted_response_enc", "UserInfo encryption method", "text"],
 ] },
 { title: "Request objects", description: "Advanced registration metadata for signed or encrypted authorization requests. Request objects are not supported by this provider yet.", fields: [
  ["request_uris", "Request URIs", "list"],
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

// Choices mirror the existing registration validator. Registration metadata
// supports more values than the runtime provider; those remain clearly marked.
export const signingAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256", "HS384", "HS512", "none"];
export const encryptionAlgorithms = ["RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW", "dir", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"];
export const encryptionMethods = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"];
export const clientListChoices: Record<string, string[]> = {
 response_types: ["code", "id_token", "id_token token", "code id_token", "code token", "code id_token token"],
 grant_types: ["authorization_code", "implicit", "refresh_token"],
};
