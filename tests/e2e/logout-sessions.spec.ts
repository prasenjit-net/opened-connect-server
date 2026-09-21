import { expect, test, type Page } from "@playwright/test";
import { AdminClient } from "../fixtures/admin-client";
import { BASE_URL, RUN_ID } from "../fixtures/constants";
import { buildAuthorizeUrl, fillLoginForm, approveConsentIfShown } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";
import { startLogoutRP } from "../fixtures/logout-relying-party";

test("local logout stays local; provider logout reaches two RPs and preserves another device", async ({browser}, testInfo) => {
 test.setTimeout(90000);
 const admin=await AdminClient.create();const a=await startLogoutRP();const b=await startLogoutRP();
 const context=await browser.newContext();const other=await browser.newContext();
 const email=`logout-${RUN_ID}@example.test`;const password="logout integration test password";
 try {
  await admin.createUser({name:"Logout User",email,password});
  const clients=[];
  for(const rp of [a,b]){const client=await admin.createClient({client_name:`Logout RP ${rp.origin}`,redirect_uris:[`${rp.origin}/callback`],token_endpoint_auth_method:"none",backchannel_logout_uri:`${rp.origin}/backchannel`,frontchannel_logout_uri:`${rp.origin}/frontchannel`,backchannel_logout_session_required:true,post_logout_redirect_uris:[`${rp.origin}/logged-out`]});rp.configure(client.client_id);clients.push(client);}
  const signIn=async(page:Page,rp:typeof a,id:string,login=false)=>{
   const {verifier,challenge}=generatePKCE();const state=randomState();rp.prepare(state,verifier);
   await page.goto(buildAuthorizeUrl({clientId:id,redirectUri:`${rp.origin}/callback`,state,nonce:randomState(),codeChallenge:challenge,scope:"openid",prompt:"consent"}));
   if(login){await page.waitForURL(/\/login\?/);await fillLoginForm(page,email,password);}
   await approveConsentIfShown(page,`${rp.origin}/protected`);await expect(page.getByRole("heading",{name:"Signed in to app"})).toBeVisible();
  };
  const page=await context.newPage();await signIn(page,a,clients[0].client_id,true);await signIn(page,b,clients[1].client_id);
  const remote=await other.newPage();await signIn(remote,b,clients[1].client_id,true);
  await page.goto(`${a.origin}/local-logout`);
  expect((await context.request.get(`${b.origin}/protected`)).status()).toBe(200);
  await signIn(page,a,clients[0].client_id);
  await page.goto(`${BASE_URL}/sessions`);
  await expect(page.getByRole("heading",{name:"Your sessions",exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Known app sessions",exact:true}).click();
  await expect(page.getByRole("cell",{name:/Logout RP/})).toHaveCount(3);
  await page.screenshot({path:testInfo.outputPath("app-sessions-desktop.png"),fullPage:true,animations:"disabled"});
  await page.setViewportSize({width:390,height:844});
  await page.emulateMedia({colorScheme:"dark"});
  await expect(page.locator("html")).toHaveAttribute("data-theme","dark");
  await expect.poll(()=>page.locator("main").evaluate(el=>Math.round(el.getBoundingClientRect().left))).toBe(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({path:testInfo.outputPath("app-sessions-mobile.png"),fullPage:true,animations:"disabled"});
  await page.goto(`${a.origin}/shared-logout`);
  await page.getByRole("button",{name:"Sign out of this provider session and connected apps"}).click();
  await expect(page.getByRole("heading",{name:"Signed out",exact:true})).toBeVisible();
  await expect.poll(async()=>(await context.request.get(`${a.origin}/protected`)).status()).toBe(401);
  await expect.poll(async()=>(await context.request.get(`${b.origin}/protected`)).status()).toBe(401);
  await expect.poll(()=>a.notifications.length).toBeGreaterThan(0);
  await expect.poll(()=>b.notifications.length).toBeGreaterThan(0);
  expect((await other.request.get(`${b.origin}/protected`)).status()).toBe(200);
  expect((await other.request.get(`${BASE_URL}/api/auth/session`)).status()).toBe(200);
  await page.getByRole("link",{name:"Continue",exact:true}).click();
  await expect(page.getByRole("heading",{name:"RP signed out"})).toBeVisible();
  expect(new URL(page.url()).searchParams.get("state")).toBe("logout-state");
  await remote.goto(`${BASE_URL}/logout`);
  await remote.getByRole("button",{name:"Cancel",exact:true}).click();
  expect((await other.request.get(`${BASE_URL}/api/auth/session`)).status()).toBe(200);
  await remote.goto(`${BASE_URL}/logout`);
  await remote.getByRole("button",{name:"Sign out of this provider session and connected apps"}).click();
  await expect.poll(async()=>(await other.request.get(`${b.origin}/protected`)).status()).toBe(401);
 } finally {await context.close();await other.close();await admin.dispose();await a.close();await b.close();}
});
