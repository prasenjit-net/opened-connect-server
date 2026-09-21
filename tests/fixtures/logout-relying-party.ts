import http from "node:http";
import { randomBytes } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { BASE_URL } from "./constants";

/** A real, disposable RP: owns its local sessions and independently verifies
 * ID/Logout Tokens. Provider notification tests assert /protected afterwards. */
export async function startLogoutRP() {
 let clientId = "";
 const pending = new Map<string, string>();
 const idTokens = new Map<string,string>();
 const sessions = new Map<string, string>(); // private cookie -> protocol sid
 const notifications: string[] = [];
 const jwks = createRemoteJWKSet(new URL(`${BASE_URL}/jwks`));
 let origin = "";
 const server = http.createServer(async (req, res) => {
  try {
   const url = new URL(req.url ?? "/", origin);
   const cookieName = `rp_${clientId}`;
   const cookie = req.headers.cookie?.split("; ").find(v => v.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
   if (url.pathname === "/callback") {
    const state = url.searchParams.get("state") ?? ""; const verifier = pending.get(state); pending.delete(state);
    if (!verifier) { res.writeHead(400); res.end("Invalid state"); return; }
    const response = await fetch(`${BASE_URL}/token`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",client_id:clientId,redirect_uri:`${origin}/callback`,code:url.searchParams.get("code") ?? "",code_verifier:verifier})});
    if (!response.ok) throw new Error(`Token exchange: ${await response.text()}`);
    const tokens = await response.json() as {id_token:string};
    const {payload} = await jwtVerify(tokens.id_token,jwks,{issuer:BASE_URL,audience:clientId,algorithms:["RS256"]});
    if (typeof payload.sid !== "string") throw new Error("Missing sid");
    const credential = randomBytes(32).toString("hex"); sessions.set(credential,payload.sid);idTokens.set(credential,tokens.id_token);
    res.setHeader("Set-Cookie",`${cookieName}=${credential}; HttpOnly; SameSite=Lax; Path=/`);
    res.writeHead(302,{Location:"/protected"});res.end();return;
   }
   if(url.pathname==="/shared-logout"){
    const hint=cookie ? idTokens.get(cookie) : undefined;if(!hint){res.writeHead(400);res.end("No app login");return;}
    const target=new URL(`${BASE_URL}/logout`);target.search=new URLSearchParams({id_token_hint:hint,client_id:clientId,post_logout_redirect_uri:`${origin}/logged-out`,state:"logout-state"}).toString();res.writeHead(302,{Location:target.toString()});res.end();return;
   }
   if(url.pathname==="/logged-out"){res.setHeader("Content-Type","text/html");res.end("<h1>RP signed out</h1>");return;}
   if (url.pathname === "/backchannel" && req.method === "POST") {
    let body="";for await (const chunk of req){body+=String(chunk);if(body.length>16000)throw new Error("Oversized request");}
    const raw=new URLSearchParams(body).get("logout_token");if(!raw)throw new Error("Missing token");
    const {payload,protectedHeader}=await jwtVerify(raw,jwks,{issuer:BASE_URL,audience:clientId,algorithms:["RS256"]});
    if(protectedHeader.typ!=="logout+jwt" || payload.nonce!==undefined || typeof payload.sid!=="string" || !payload.jti || !payload.events || !(payload.events as Record<string,unknown>)["http://schemas.openid.net/event/backchannel-logout"])throw new Error("Invalid logout claims"); // NOSONAR: required OIDC event identifier, never used for HTTP transport.
    for(const [key,sid] of sessions){if(sid===payload.sid)sessions.delete(key);}
    notifications.push(payload.sid);res.writeHead(200);res.end();return;
   }
   if(url.pathname==="/frontchannel"){
    if(url.searchParams.get("iss")!==BASE_URL){res.writeHead(400);res.end();return;}
    for(const [key,sid] of sessions){if(sid===url.searchParams.get("sid"))sessions.delete(key);}
    res.setHeader("Cache-Control","no-store");res.end("Logout processed");return;
   }
   if(url.pathname==="/local-logout"){
    if(cookie) { sessions.delete(cookie); }
    res.setHeader("Set-Cookie",`${cookieName}=; Max-Age=0; Path=/`);res.end("Locally signed out");return;
   }
   if(url.pathname==="/protected"){
    const active=!!cookie && sessions.has(cookie);res.writeHead(active?200:401,{"Content-Type":"text/html"});res.end(`<h1>${active?"Signed in to app":"App session ended"}</h1>`);return;
   }
   res.writeHead(404);res.end();
  } catch { res.writeHead(400);res.end("Invalid protocol message"); }
 });
 await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
 const address=server.address();if(!address || typeof address==="string")throw new Error("No RP listener");origin=`http://127.0.0.1:${address.port}`;
 return {origin,notifications,configure:(id:string)=>{clientId=id;},prepare:(state:string,verifier:string)=>pending.set(state,verifier),close:()=>new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()))};
}
