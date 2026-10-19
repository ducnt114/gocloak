#!/usr/bin/env python3
"""SAML interoperability check: a real Keycloak acts as the service provider
(a SAML identity provider of a Keycloak realm) and gocloak as the identity
provider. For each variant the script logs in through the broker, checks the
attributes Keycloak mapped from the assertion, then logs out from Keycloak,
which sends a signed LogoutRequest to gocloak and validates its answer.

    scripts/compat/saml_sp.py --keycloak http://localhost:8180 --gocloak http://localhost:8080

Both servers need a master realm admin "admin" / "admin", and Keycloak must
reach gocloak's URL (it downloads the IdP metadata).
"""
import argparse
import html
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from tokens import admin_token, call

VARIANTS = {
    "post binding, signed response and assertion": {},
    "encrypted assertion": {"idp": {"wantAssertionsEncrypted": "true"}},
    "redirect binding": {"idp": {"postBindingResponse": "false", "postBindingAuthnRequest": "false", "postBindingLogout": "false"},
                         "client": {"saml.force.post.binding": "false"}},
    "inclusive canonicalization, RSA-SHA512": {"client": {
        "saml_signature_canonicalization_method": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "saml.signature.algorithm": "RSA_SHA512"}},
}


def must(cond, what):
    if not cond:
        sys.exit("FAIL: " + what)


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a):
                return None
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def go(self, url, form=None):
        for c in self.jar:  # Keycloak marks its cookies Secure, even over http
            c.secure = False
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        try:
            r = self.op.open(urllib.request.Request(url, data=data))
            return r.status, r.headers, r.read().decode(), url
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode(), url

    def follow(self, resp, limit=20):
        """Follows redirects and auto-posted SAML forms."""
        st, h, body, url = resp
        for _ in range(limit):
            if st in (301, 302, 303):
                st, h, body, url = self.go(urllib.parse.urljoin(url, h["Location"]))
                continue
            fields = hidden_fields(body)
            if "SAMLRequest" in fields or "SAMLResponse" in fields:
                st, h, body, url = self.go(urllib.parse.urljoin(url, form_action(body)), fields)
                continue
            break
        return st, h, body, url


def hidden_fields(body):
    return {m[0]: html.unescape(m[1]) for m in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', body)}


def form_action(body):
    m = re.search(r'<form[^>]*action="([^"]+)"', body)
    must(m, "no form in page: " + body[:500])
    return html.unescape(m.group(1))


def setup(kc, gc, variant):
    kt, gt = admin_token(kc), admin_token(gc)
    call("DELETE", gc + "/admin/realms/samlidp", gt)
    must(call("POST", gc + "/admin/realms", gt, body={"realm": "samlidp", "enabled": True})[0] == 201, "create gocloak realm")
    call("POST", gc + "/admin/realms/samlidp/users", gt, body={
        "username": "carol", "enabled": True, "email": "carol@example.org", "firstName": "Carol", "lastName": "Cooper",
        "credentials": [{"type": "password", "value": "carol-pw", "temporary": False}]})
    call("DELETE", kc + "/admin/realms/kcsp", kt)
    must(call("POST", kc + "/admin/realms", kt, body={"realm": "kcsp", "enabled": True})[0] == 201, "create Keycloak realm")
    st, cfg, _ = call("POST", kc + "/admin/realms/kcsp/identity-provider/import-config", kt,
                      body={"providerId": "saml", "fromUrl": gc + "/realms/samlidp/protocol/saml/descriptor"})
    must(st == 200, f"Keycloak imports the gocloak descriptor: {st} {cfg}")
    cfg.update({"postBindingResponse": "true", "postBindingAuthnRequest": "true", "postBindingLogout": "true",
                "wantAssertionsSigned": "true", "validateSignature": "true", "principalType": "SUBJECT", "syncMode": "FORCE"})
    cfg.update(variant.get("idp", {}))
    st, b, _ = call("POST", kc + "/admin/realms/kcsp/identity-provider/instances", kt,
                    body={"alias": "gc", "providerId": "saml", "enabled": True, "config": cfg})
    must(st == 201, f"create the Keycloak identity provider: {st} {b}")
    for attr in ("email", "firstName", "lastName"):
        call("POST", kc + "/admin/realms/kcsp/identity-provider/instances/gc/mappers", kt, body={
            "name": attr, "identityProviderAlias": "gc", "identityProviderMapper": "saml-user-attribute-idp-mapper",
            "config": {"attribute.name": attr, "user.attribute": attr, "syncMode": "INHERIT"}})
    # register Keycloak's SP metadata in gocloak through the description converter
    meta = urllib.request.urlopen(kc + "/realms/kcsp/broker/gc/endpoint/descriptor").read()
    req = urllib.request.Request(gc + "/admin/realms/samlidp/client-description-converter", data=meta,
                                 headers={"Authorization": "Bearer " + gt, "Content-Type": "application/xml"})
    rep = json.load(urllib.request.urlopen(req))
    rep["attributes"].update(variant.get("client", {}))
    rep["protocolMappers"] = [{"name": a, "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
                               "config": {"user.attribute": a, "attribute.name": a}} for a in ("email", "firstName", "lastName")]
    st, b, _ = call("POST", gc + "/admin/realms/samlidp/clients", gt, body=rep)
    must(st == 201, f"create the gocloak SAML client: {st} {b}")
    return kt, gt


def gocloak_sessions(gc, gt):
    st, users, _ = call("GET", gc + "/admin/realms/samlidp/users?username=carol", gt)
    return len(call("GET", gc + f"/admin/realms/samlidp/users/{users[0]['id']}/sessions", gt)[1])


def run(kc, gc, variant):
    kt, gt = setup(kc, gc, variant)
    b = Browser()
    auth = kc + "/realms/kcsp/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": "account-console", "redirect_uri": kc + "/realms/kcsp/account/", "response_type": "code",
        "scope": "openid", "kc_idp_hint": "gc", "code_challenge_method": "S256",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"})
    st, h, body, url = b.follow(b.go(auth))
    must(url.startswith(gc) and 'name="password"' in body, f"sent to the gocloak login page ({url})")
    st, h, body, url = b.follow(b.go(form_action(body), {"username": "carol", "password": "carol-pw"}))
    # Keycloak's first broker login asks to review the profile
    if "Update Account Information" in body or 'name="firstName"' in body:
        prefill = dict(re.findall(r'name="(username|email|firstName|lastName)"[^>]*value="([^"]*)"', body))
        must(prefill.get("email") == "carol@example.org" and prefill.get("firstName") == "Carol",
             f"attributes of the assertion: {prefill}")
        st, h, body, url = b.follow(b.go(urllib.parse.urljoin(url, form_action(body)), prefill))
    must(st == 200 and "/realms/kcsp/account" in url, f"logged in to Keycloak ({st} {url})")
    st, users, _ = call("GET", kc + "/admin/realms/kcsp/users?briefRepresentation=false", kt)
    must(len(users) == 1 and users[0].get("email") == "carol@example.org" and users[0].get("lastName") == "Cooper",
         f"brokered Keycloak user: {users}")
    must(gocloak_sessions(gc, gt) == 1, "gocloak session after login")

    # logout from Keycloak: a LogoutRequest to gocloak and back
    st, h, body, url = b.go(kc + "/realms/kcsp/protocol/openid-connect/logout")
    form = dict(re.findall(r'name="(session_code)"[^>]*value="([^"]*)"', body))
    form["confirmLogout"] = "Logout"
    st, h, body, url = b.follow(b.go(urllib.parse.urljoin(url, form_action(body)), form))
    must("You are logged out" in body, f"Keycloak logout page ({st} {url})")
    must(gocloak_sessions(gc, gt) == 0, "gocloak session after the SAML logout")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keycloak", required=True)
    ap.add_argument("--gocloak", required=True)
    args = ap.parse_args()
    for name, variant in VARIANTS.items():
        run(args.keycloak.rstrip("/"), args.gocloak.rstrip("/"), variant)
        print("ok:", name)


if __name__ == "__main__":
    main()
