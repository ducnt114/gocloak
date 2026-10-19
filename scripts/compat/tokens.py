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


VOLATILE = {"exp", "iat", "jti", "sid", "auth_time", "sub", "at_hash", "session_state", "nonce", "clientHost", "clientAddress",
            "reuse_id", "lastFailure", "failedLoginNotBefore", "lastIPFailure"}


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
    out.update(security(base))
    out.update(authentication(base))
    return out


def authentication(base):
    """User profile, required actions and authentication flows."""
    out = {}
    tok = admin_token(base)
    r = base + "/admin/realms/" + REALM
    t = base + f"/realms/{REALM}/protocol/openid-connect/token"
    st, body, _ = call("POST", r + "/users", tok, {"username": "x", "email": "nope", "enabled": True})
    out["profile.single-error"] = {"status": st, "body": body}
    st, body, _ = call("POST", r + "/users", tok, {"username": "ab", "email": "nope"})
    out["profile.multiple-errors"] = {"status": st, "body": body}
    st, body, h = call("POST", r + "/users", tok, {"username": "noprofile", "enabled": True,
                                                  "credentials": [{"type": "password", "value": "pw", "temporary": False}]})
    must(st, 201, "create noprofile", body)
    st, body, _ = call("POST", t, form={"grant_type": "password", "client_id": "web", "client_secret": "web-secret",
                                        "username": "noprofile", "password": "pw"})
    out["profile.incomplete-login"] = {"status": st, "body": body}
    st, body, _ = call("PUT", r + "/users/" + h["Location"].rsplit("/", 1)[1] + "/execute-actions-email", tok, ["UPDATE_PASSWORD"])
    out["email.missing"] = {"status": st, "body": body}
    st, body, _ = call("GET", r + "/users/profile", tok)
    out["profile.default"] = body
    st, body, _ = call("GET", r + "/authentication/required-actions", tok)
    out["required-actions"] = [{k: a[k] for k in ("alias", "name", "providerId", "enabled", "defaultAction", "priority")} for a in body]
    for alias in ["browser", "direct grant", "registration", "reset credentials", "clients"]:
        st, body, _ = call("GET", r + "/authentication/flows/" + urllib.parse.quote(alias) + "/executions", tok)
        out["flow." + alias.replace(" ", "-")] = [{k: e.get(k) for k in ("level", "index", "displayName", "requirement", "providerId",
                                                                         "requirementChoices", "authenticationFlow")} for e in body]
    st, body, _ = call("POST", r + "/authentication/flows/browser/executions/execution", tok, {"provider": "auth-otp-form"})
    out["flow.builtin-edit"] = {"status": st, "body": body}
    return out


def security(base):
    """Password policy, brute force, offline and refresh token behaviour."""
    out = {}
    tok = admin_token(base)
    r = base + "/admin/realms/" + REALM
    t = base + f"/realms/{REALM}/protocol/openid-connect/token"

    def realm(settings):
        st, body, _ = call("PUT", r, tok, settings)
        must(st, 204, "update realm", body)

    def password(user, pw, **extra):
        form = {"grant_type": "password", "client_id": "web", "client_secret": "web-secret", "username": user, "password": pw}
        form.update(extra)
        return call("POST", t, form=form)[:2]

    def refresh(token):
        return call("POST", t, form={"grant_type": "refresh_token", "client_id": "web", "client_secret": "web-secret",
                                     "refresh_token": token})[:2]

    def outcome(st, body):
        if isinstance(body, dict):
            return {"status": st, "error": body.get("error"), "error_description": body.get("error_description")}
        return {"status": st}

    st, body, h = call("POST", r + "/users", tok, {"username": "mallory", "email": "mallory@example.com", "firstName": "M",
                                                  "lastName": "M", "enabled": True,
                                                  "credentials": [{"type": "password", "value": "pass1234", "temporary": False}]})
    must(st, 201, "create mallory", body)
    mallory = h["Location"].rsplit("/", 1)[1]

    realm({"passwordPolicy": "length(8) and digits(1) and passwordHistory(1)"})
    for name, pw in [("short", "short"), ("no-digit", "abcdefgh"), ("history", "pass1234")]:
        st, body, _ = call("PUT", f"{r}/users/{mallory}/reset-password", tok, {"type": "password", "value": pw, "temporary": False})
        out["policy." + name] = outcome(st, body)
    realm({"passwordPolicy": ""})

    st, body = password("mallory", "pass1234")
    out["refresh.claims"] = normalise(decode(body["refresh_token"]), base)
    out["refresh.response"] = {"refresh_expires_in": body["refresh_expires_in"] > 0, "not-before-policy": body["not-before-policy"]}
    st, body = password("mallory", "pass1234", scope="openid offline_access")
    out["offline.claims"] = normalise(decode(body["refresh_token"]), base)
    out["offline.response"] = {"refresh_expires_in": body["refresh_expires_in"], "scope": " ".join(sorted(body["scope"].split()))}
    st, body = refresh(body["refresh_token"])
    out["offline.refresh"] = {"status": st, "typ": decode(body["refresh_token"])["typ"] if st == 200 else None}

    realm({"revokeRefreshToken": True, "refreshTokenMaxReuse": 1})
    st, body = password("mallory", "pass1234")
    first = body["refresh_token"]
    st, body = refresh(first)
    second = body["refresh_token"]
    seq = [outcome(st, body)]
    seq.append(outcome(*refresh(first)))
    seq.append(outcome(*refresh(first)))
    seq.append(outcome(*refresh(second)))
    out["rotation"] = [{"status": x["status"], "error_description": x.get("error_description")} for x in seq]
    realm({"revokeRefreshToken": False})

    realm({"bruteForceProtected": True, "failureFactor": 2, "waitIncrementSeconds": 60, "quickLoginCheckMilliSeconds": 0})
    attempts = [outcome(*password("mallory", "wrong")), outcome(*password("mallory", "wrong")),
                outcome(*password("mallory", "pass1234"))]
    out["bruteforce.attempts"] = attempts
    st, status, _ = call("GET", f"{r}/attack-detection/brute-force/users/{mallory}", tok)
    out["bruteforce.status"] = normalise(status, base)
    st, user, _ = call("GET", f"{r}/users/{mallory}", tok)
    out["bruteforce.user-enabled"] = {"enabled": user["enabled"]}
    call("DELETE", f"{r}/attack-detection/brute-force/users/{mallory}", tok)
    out["bruteforce.after-clear"] = outcome(*password("mallory", "pass1234"))["status"]
    realm({"bruteForceProtected": False})
    out["bruteforce.after-clear"] = {"status": out["bruteforce.after-clear"]}
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
