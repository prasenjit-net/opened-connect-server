export interface ScopeInfo {
  scope: string;
  description: string;
}

export interface TransactionView {
  status: "complete" | "consent_required" | "error";
  redirectTo?: string;
  clientName?: string;
  scopes?: ScopeInfo[];
  message?: string;
}
