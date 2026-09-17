export interface InitialToken {
 id: string; label: string; issuedBy: string; issuedAt: string; expiresAt: string;
 maxUses: number; uses: number; status: "active" | "expired" | "consumed" | "revoked";
}
export interface InitialTokenList { tokens: InitialToken[]; total: number; page: number; pageSize: number; }
export interface RegistrationSettings { enabled: boolean; endpoint: string; }
