export const activityKinds = ["transactions", "codes", "tokens", "consents", "refresh"] as const;
export type ActivityKind = typeof activityKinds[number];
export const activityLabels: Record<ActivityKind, string> = { transactions: "Transactions", codes: "Authorization codes", tokens: "Access tokens", consents: "Consents", refresh: "Refresh tokens" };
export interface ActivityRecord {
 grantType?: string; audience?: string; subjectKind?: string; familyId?: string; absoluteExpiry?: string; idleExpiry?: string;
 id: string; kind: ActivityKind; status: string; clientId: string; clientName: string;
 userId?: string; userName?: string; userEmail?: string; scopes: string[];
 createdAt: string | null; expiresAt: string | null; idTokenExpiresAt?: string; canRevoke: boolean;
}
export interface ActivityList { records: ActivityRecord[]; total: number; page: number; pageSize: number; }
export interface ActivityCounts { total: number; active: number; revoked: number; expired: number; completed: number; consumed: number; }
export interface ActivityOverview { sessions?: Record<string, number>; generatedAt: string; protocolEnabled: boolean; users: number; clients: number; counts: Record<ActivityKind, ActivityCounts>; recent: ActivityRecord[]; }
export function activityDate(value?: string | null) { return value ? new Date(value).toLocaleString() : "—"; }
