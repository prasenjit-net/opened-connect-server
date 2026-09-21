import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import SessionsPage from "./pages/Sessions";
import { api } from "./lib/api";
import type { SessionRecord } from "./lib/sessions";

vi.mock("./context/AuthContext", () => ({ useAuth: () => ({user:{id:"user"},forget:vi.fn()}) }));
vi.mock("./components/ActivityNavigation", () => ({default: () => <nav>Activity</nav>}));
const row: SessionRecord = {id:"session-1",kind:"op-sessions",userId:"user",userName:"User",opSessionId:"session-1",status:"active",current:false,createdAt:"2026-01-01",lastSeenAt:"2026-01-01",expiresAt:"2026-01-02",endedAt:"0001-01-01",appCount:2,deliveryStatuses:[]};
beforeEach(() => {
 HTMLDialogElement.prototype.showModal = function(){this.setAttribute("open","");};
 HTMLDialogElement.prototype.close = function(){this.removeAttribute("open");};
 vi.spyOn(api,"sessionActivity").mockResolvedValue({records:[row],total:1,page:1,pageSize:10});
 vi.spyOn(api,"endSession").mockResolvedValue({localOutcome:"ended",deliveryStatus:"pending_or_unconfirmed"});
});
function setup(admin=false){render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}})}><SessionsPage admin={admin}/></QueryClientProvider>);}
it("requires confirmation, reports pending delivery, and preserves other sessions",async()=>{
 setup();await userEvent.click(await screen.findByRole("button",{name:"Sign out"}));
 expect(api.endSession).not.toHaveBeenCalled();expect(screen.getByRole("dialog")).toHaveTextContent("this provider session");
 await userEvent.click(screen.getByRole("button",{name:"Confirm"}));
 expect(await screen.findByRole("status")).toHaveTextContent("notifications may be pending");
 expect(api.endSession).toHaveBeenCalledWith("op-sessions","session-1",false,{password:"",scope:undefined,revokeOffline:false});
});
it("requires password for all-session action and does not default to revoking offline access",async()=>{
 setup();await userEvent.click(await screen.findByRole("button",{name:"Sign out all sessions"}));
 expect(screen.getByLabelText("Confirm your password")).toBeRequired();expect(screen.getByRole("checkbox")).not.toBeChecked();
 await userEvent.click(screen.getByRole("button",{name:"Cancel"}));expect(api.endSession).not.toHaveBeenCalled();
});
it("keeps failures visible and does not report success",async()=>{
 vi.mocked(api.endSession).mockRejectedValue(new Error("Session changed"));setup();await userEvent.click(await screen.findByRole("button",{name:"Sign out"}));await userEvent.click(screen.getByRole("button",{name:"Confirm"}));
 expect(await screen.findByRole("alert")).toHaveTextContent("Session changed");expect(screen.queryByRole("status")).not.toBeInTheDocument();
});
it("links provider rows to filtered app associations",async()=>{
 setup();await userEvent.click(await screen.findByRole("button",{name:"View apps"}));
 await waitFor(()=>expect(api.sessionActivity).toHaveBeenLastCalledWith("app-sessions",false,{q:"session-1",status:"",page:1},expect.any(AbortSignal)));
});
