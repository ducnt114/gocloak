#!/usr/bin/env python3
"""Compare the tokens issued by gocloak and by a real Keycloak.

Both servers get the same realm (created through the admin REST API), then
the script requests tokens for a few scenarios and prints the normalised
claims side by side. With --golden DIR it writes Keycloak's normalised claims
as golden files used by internal/server/compat_test.go.

    scripts/compat/tokens.py --keycloak http://localhost:8180 --gocloak http://localhost:8080
    scripts/compat/tokens.py --keycloak http://localhost:8180 --golden internal/server/testdata/keycloak

Both servers need a master realm admin "admin" / "admin".
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

REALM = "compat"


def call(method, url, token=None, body=None, form=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None), resp.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw), e.headers
        except ValueError:
            return e.code, raw.decode(errors="replace"), e.headers


def must(status, want, what, body):
    if status != want:
        sys.exit(f"{what}: expected {want}, got {status}: {body}")


def admin_token(base):
    st, body, _ = call("POST", base + "/realms/master/protocol/openid-connect/token",
                       form={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    must(st, 200, "admin token", body)
    return body["access_token"]


def setup(base):
    tok = admin_token(base)
    a = base + "/admin/realms"
    call("DELETE", f"{a}/{REALM}", tok)
    st, body, _ = call("POST", a, tok, {"realm": REALM, "enabled": True})
    must(st, 201, "create realm", body)
    r = f"{a}/{REALM}"
    for c in [
        {"clientId": "web", "secret": "web-secret", "redirectUris": ["http://app.test/*"], "webOrigins": ["+"],
         "directAccessGrantsEnabled": True},
        {"clientId": "svc", "secret": "svc-secret", "serviceAccountsEnabled": True, "standardFlowEnabled": False},
        {"clientId": "narrow", "secret": "narrow-secret", "directAccessGrantsEnabled": True, "fullScopeAllowed": False,
         "redirectUris": ["http://narrow.test/*"]},
    ]:
        st, body, _ = call("POST", r + "/clients", tok, c)
        must(st, 201, "create client " + c["clientId"], body)

    def client_uuid(cid):
        _, body, _ = call("GET", f"{r}/clients?clientId={cid}", tok)
        return body[0]["id"]

    web, narrow = client_uuid("web"), client_uuid("narrow")
    for name in ["editor", "auditor"]:
        st, body, _ = call("POST", r + "/roles", tok, {"name": name})
        must(st, 201, "create role " + name, body)
    st, body, _ = call("POST", f"{r}/clients/{web}/roles", tok, {"name": "viewer"})
    must(st, 201, "create client role", body)
    st, body, h = call("POST", r + "/groups", tok, {"name": "staff"})
    must(st, 201, "create group", body)
    group = h["Location"].rsplit("/", 1)[1]
    _, editor, _ = call("GET", r + "/roles/editor", tok)
    call("POST", f"{r}/groups/{group}/role-mappings/realm", tok, [editor])

    st, body, h = call("POST", r + "/users", tok, {
        "username": "alice", "email": "alice@example.com", "firstName": "Alice", "lastName": "Liddell",
        "enabled": True, "emailVerified": True,
        "credentials": [{"type": "password", "value": "wonderland", "temporary": False}],
    })
    must(st, 201, "create user", body)
    user = h["Location"].rsplit("/", 1)[1]
    call("PUT", f"{r}/users/{user}/groups/{group}", tok)
    _, viewer, _ = call("GET", f"{r}/clients/{web}/roles/viewer", tok)
    call("POST", f"{r}/users/{user}/role-mappings/clients/{web}", tok, [viewer])
    _, auditor, _ = call("GET", r + "/roles/auditor", tok)
    call("POST", f"{r}/users/{user}/role-mappings/realm", tok, [auditor])
    # narrow only sees "auditor" through a scope mapping. (User attributes
    # are left out: Keycloak 26 drops attributes not declared in the user
    # profile, while gocloak keeps them.)
    call("POST", f"{r}/clients/{narrow}/scope-mappings/realm", tok, [auditor])
    # a hardcoded claim on web
    st, body, _ = call("POST", f"{r}/clients/{web}/protocol-mappers/models", tok, {
        "name": "tenant", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "tenant.id", "claim.value": "42", "jsonType.label": "long",
                   "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}})
    must(st, 201, "create mapper", body)


def decode(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


VOLATILE = {"exp", "iat", "jti", "sid", "auth_time", "sub", "at_hash", "session_state", "nonce", "clientHost", "clientAddress"}


def normalise(claims, base):
    def walk(v):
        if isinstance(v, dict):
            return {k: ("<volatile>" if k in VOLATILE else walk(x)) for k, x in sorted(v.items())}
        if isinstance(v, list):
            items = [walk(x) for x in v]
            return sorted(items, key=json.dumps)
        if isinstance(v, str):
            return v.replace(base, "{base}")
        return v
    out = walk(claims)
    # the order of names in "scope" is not significant
    if isinstance(out, dict) and isinstance(out.get("scope"), str):
        out["scope"] = " ".join(sorted(out["scope"].split()))
    return out


def scenarios(base):
    t = base + f"/realms/{REALM}/protocol/openid-connect/token"
    u = base + f"/realms/{REALM}/protocol/openid-connect/userinfo"
    out = {}

    def password(client, secret, scope):
        form = {"grant_type": "password", "client_id": client, "client_secret": secret,
                "username": "alice", "password": "wonderland"}
        if scope:
            form["scope"] = scope
        st, body, _ = call("POST", t, form=form)
        must(st, 200, f"password grant {client} {scope}", body)
        return body

    for name, client, secret, scope in [
        ("default", "web", "web-secret", "openid"),
        ("optional-scopes", "web", "web-secret", "openid address phone microprofile-jwt"),
        ("no-openid", "web", "web-secret", ""),
        ("narrow", "narrow", "narrow-secret", "openid"),
    ]:
        body = password(client, secret, scope)
        out[name + ".access"] = normalise(decode(body["access_token"]), base)
        if "id_token" in body:
            out[name + ".id"] = normalise(decode(body["id_token"]), base)
        st, info, _ = call("GET", u, body["access_token"])
        out[name + ".userinfo"] = normalise(info, base) if st == 200 else {"status": st}
        out[name + ".response"] = {"scope": " ".join(sorted(body["scope"].split())), "token_type": body["token_type"]}

    st, body, _ = call("POST", t, form={"grant_type": "client_credentials", "client_id": "svc", "client_secret": "svc-secret"})
    must(st, 200, "client credentials", body)
    out["client-credentials.access"] = normalise(decode(body["access_token"]), base)
    out["client-credentials.response"] = {"scope": " ".join(sorted(body["scope"].split())), "refresh": "refresh_token" in body}

    st, body, _ = call("POST", t, form={"grant_type": "password", "client_id": "web", "client_secret": "web-secret",
                                        "username": "alice", "password": "wonderland", "scope": "openid nope"})
    out["invalid-scope"] = {"status": st, "error": body.get("error") if isinstance(body, dict) else body}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keycloak", required=True)
    ap.add_argument("--gocloak")
    ap.add_argument("--golden")
    args = ap.parse_args()

    setup(args.keycloak)
    kc = scenarios(args.keycloak)
    if args.golden:
        import os
        os.makedirs(args.golden, exist_ok=True)
        for name, claims in kc.items():
            with open(os.path.join(args.golden, name + ".json"), "w") as f:
                json.dump(claims, f, indent=2, sort_keys=True)
                f.write("\n")
        print(f"wrote {len(kc)} golden files to {args.golden}")
    if args.gocloak:
        setup(args.gocloak)
        gc = scenarios(args.gocloak)
        diffs = 0
        for name in sorted(set(kc) | set(gc)):
            a, b = kc.get(name), gc.get(name)
            if a != b:
                diffs += 1
                print(f"--- {name}\n  keycloak: {json.dumps(a, sort_keys=True)}\n  gocloak:  {json.dumps(b, sort_keys=True)}")
        print(f"{diffs} differences")
        sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
