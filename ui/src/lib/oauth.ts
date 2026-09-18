export interface OAuthResource { audience: string; scopes: string[]; enabled: boolean; }
export interface OAuthSettings { resources: OAuthResource[]; passwordGrantEnabled: boolean; refreshTokensEnabled: boolean; protocolEnabled: boolean; }
export interface ResourceScopes { allowed: string[]; default: string[]; }
export interface OAuthPolicy {
 grants: string[]; resources: Record<string, ResourceScopes>; defaultResource: string;
 introspectionEnabled: boolean; introspectionAudiences: string[]; refreshInspection: boolean;
 refreshEnabled: boolean; passwordEnabled: boolean;
}
export type OAuthAccess = Record<string, string[]>;
