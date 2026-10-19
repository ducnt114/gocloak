#!/usr/bin/env python3
"""Creates the realm "oidf" tested by the OpenID conformance suite: a user with
all standard claims and three confidential clients redirecting to the suite.

usage: setup.py ADMIN_BASE_URL SUITE_BASE_URL
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "compat"))
from tokens import call, admin_token  # noqa: E402
B, SUITE = sys.argv[1], sys.argv[2].rstrip("/")
t = admin_token(B); R = B + "/admin/realms"
call("DELETE", R + "/oidf", t)
st, b, _ = call("POST", R, t, body={"realm": "oidf", "enabled": True})
assert st == 201, b
# user profile: allow the standard claims as attributes
st, up, _ = call("GET", R + "/oidf/users/profile", t)
up["unmanagedAttributePolicy"] = "ENABLED"
print("profile", call("PUT", R + "/oidf/users/profile", t, body=up)[0])
st, b, _ = call("POST", R + "/oidf/users", t, body={"username": "oidf-user", "enabled": True, "email": "oidf@example.org", "emailVerified": True,
    "firstName": "Oidf", "lastName": "User", "attributes": {"phoneNumber": ["+1 555 0100"], "phoneNumberVerified": ["true"],
    "street": ["1 Main St"], "locality": ["Springfield"], "region": ["OR"], "postal_code": ["97475"], "country": ["US"],
    "formatted": ["1 Main St, Springfield, OR 97475, US"], "middleName": ["Q"], "nickname": ["oidf"], "website": ["https://example.org"],
    "gender": ["other"], "birthdate": ["1990-01-01"], "zoneinfo": ["Europe/Paris"], "locale": ["en"], "picture": ["https://example.org/p.png"],
    "profile": ["https://example.org/oidf"]},
    "credentials": [{"type": "password", "value": "oidf-password", "temporary": False}]})
print("user", st, b)
redirect = [SUITE + "/test/a/gocloak/callback", SUITE + "/test/a/gocloak/callback?dummy1=lorem&dummy2=ipsum"]
for cid in ("oidf1", "oidf2", "oidf-post"):
    rep = {"clientId": cid, "secret": cid + "-secret", "redirectUris": redirect, "directAccessGrantsEnabled": False,
           "attributes": {"post.logout.redirect.uris": SUITE + "/test/a/gocloak/post_logout_redirect"}}
    st, b, _ = call("POST", R + "/oidf/clients", t, body=rep)
    print(cid, st, b)
