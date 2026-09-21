package oidc

import "net/http"

// The logout pages stay usable after authentication is removed and load no
// third-party resources. System color preferences also work without the SPA.
func (s *Service) LogoutStyleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(`:root{color-scheme:light dark;font-family:system-ui,-apple-system,sans-serif;background:#f4f5f8;color:#1d2433}body{margin:0;display:grid;min-height:100svh;place-items:center}main{box-sizing:border-box;width:min(92vw,38rem);margin:2rem auto;padding:2.5rem;border:1px solid #dbe0e9;border-radius:1rem;background:#fff;box-shadow:0 12px 40px #1d24330a}h1{font-size:1.7rem;margin:0 0 1rem}p{line-height:1.7;color:#526078}form{display:flex;gap:.8rem;flex-wrap:wrap;margin-top:1.5rem}button,a{font:inherit}button{cursor:pointer;padding:.8rem 1rem;border:1px solid #dbe0e9;border-radius:.5rem;background:#fff;color:inherit}button[value=logout]{background:#405de6;border-color:#405de6;color:white}a{color:#405de6}button:focus-visible,a:focus-visible{outline:3px solid #8ca2ff;outline-offset:3px}@media(prefers-color-scheme:dark){:root{background:#111723;color:#edf1f7}main{background:#192232;border-color:#344258}p{color:#b5c0d2}button{background:#263248;border-color:#46536a}a{color:#a7b7ff}}@media(max-width:480px){main{padding:1.5rem}button{width:100%}}`))
}
