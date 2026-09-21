export const sessionKinds = ["op-sessions", "app-sessions", "logout-events"] as const;
export type SessionKind = typeof sessionKinds[number];
export const sessionLabels: Record<SessionKind, string> = { "op-sessions": "Provider sessions", "app-sessions": "Known app sessions", "logout-events": "Logout events" };
export interface SessionRecord {
 id: string; kind: SessionKind; userId: string; userName: string; clientId?: string; clientName?: string;
 opSessionId: string; status: string; current: boolean; device?: string;
 createdAt: string; lastSeenAt: string; expiresAt: string; endedAt: string; reason?: string;
 errorCode?: string; nextAttempt?: string; history?: {at:string;httpStatus?:number;errorCode?:string}[];
 actor?: string; channel?: string; attempts?: number; httpStatus?: number; appCount: number; deliveryStatuses: string[];
}
export interface SessionList { records: SessionRecord[]; total: number; page: number; pageSize: number }
export interface LogoutResult { operationId?: string; localOutcome: string; deliveryStatus: string; continueTo?: string }
