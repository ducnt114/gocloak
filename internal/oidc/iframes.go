package oidc

import (
	"net/http"
)

// Pages keycloak-js loads in iframes: the third-party cookie check and the
// login status iframe, which compares the KEYCLOAK_SESSION cookie with the
// application's session.

const step1Page = `<!doctype html>
<html><head><meta charset="utf-8"></head><body><script type="module">
async function hasStorageAccess() {
  if (!("hasStorageAccess" in document)) return true;
  if (await document.hasStorageAccess()) return true;
  try { await document.requestStorageAccess(); return true; } catch (e) { return false; }
}
if (await hasStorageAccess()) {
  document.cookie = "KEYCLOAK_3P_COOKIE_SAMESITE=supported; Max-Age=60; SameSite=None; Secure";
  document.cookie = "KEYCLOAK_3P_COOKIE=supported; Max-Age=60";
  window.location = "step2.html";
} else {
  window.parent.postMessage("unsupported", "*");
}
</script></body></html>`

const step2Page = `<!doctype html>
<html><head><meta charset="utf-8"></head><body><script type="module">
const supported = document.cookie.includes("KEYCLOAK_3P_COOKIE");
if (supported) {
  document.cookie = "KEYCLOAK_3P_COOKIE_SAMESITE=; Max-Age=0";
  document.cookie = "KEYCLOAK_3P_COOKIE=; Max-Age=0";
}
window.parent.postMessage(supported ? "supported" : "unsupported", "*");
</script></body></html>`

const loginStatusPage = `<!doctype html>
<html><head><meta charset="utf-8"></head><body><script type="module">
let init;
let requested = false;
async function hasStorageAccess() {
  if (!("hasStorageAccess" in document)) return true;
  if (await document.hasStorageAccess()) return true;
  try { await document.requestStorageAccess(); return true; } catch (e) { return false; }
}
function sessionCookie() {
  for (const c of document.cookie.split(";")) {
    const [k, v] = c.split("=").map((x) => x.trim());
    if (k === "KEYCLOAK_SESSION") return v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : v;
  }
  return null;
}
async function checkState(clientId, origin, sessionState) {
  if (!(await hasStorageAccess())) return "error";
  if (!init) {
    if (requested) return "error";
    requested = true;
    const url = new URL(location.origin + location.pathname + "/init");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("origin", origin);
    const res = await fetch(url);
    if (!res.ok) return "error";
    init = { clientId, origin };
  }
  const cookie = sessionCookie();
  if (!cookie) return sessionState !== "" ? "changed" : "unchanged";
  if (clientId === init.clientId && origin === init.origin) {
    return sessionState === cookie.split("/")[2] ? "unchanged" : "changed";
  }
  return "error";
}
window.addEventListener("message", async (event) => {
  if (typeof event.data !== "string") return;
  const data = event.data.split(" ");
  if (data.length !== 2) return;
  event.source.postMessage(await checkState(data[0], event.origin, data[1]), event.origin);
});
</script></body></html>`

func (h *Handler) iframePage(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := h.realm(r); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, must-revalidate, no-transform, no-store")
		w.Header().Set("Content-Security-Policy", "frame-src 'self'; object-src 'none';")
		w.Write([]byte(page))
	}
}

// loginStatusInit checks that a client may use the login status iframe
// from an origin.
func (h *Handler) loginStatusInit(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, r.URL.Query().Get("client_id"))
	if err != nil || !c.Enabled || !webOriginAllowed(h.URLs.Base(r), c, r.URL.Query().Get("origin")) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) registerIframes(mux *http.ServeMux) {
	const p = "/realms/{realm}/protocol/openid-connect"
	mux.HandleFunc("GET "+p+"/3p-cookies/step1.html", h.iframePage(step1Page))
	mux.HandleFunc("GET "+p+"/3p-cookies/step2.html", h.iframePage(step2Page))
	mux.HandleFunc("GET "+p+"/login-status-iframe.html", h.iframePage(loginStatusPage))
	mux.HandleFunc("GET "+p+"/login-status-iframe.html/init", h.loginStatusInit)
}
