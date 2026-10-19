"""Builds internal/admin/serverinfo.json, the catalog behind GET /admin/serverinfo,
from the serverinfo of a Keycloak server, keeping only what gocloak supports.

usage: python3 serverinfo.py KEYCLOAK_URL  (admin/admin on the master realm)
"""
import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from tokens import call, admin_token

B = sys.argv[1]
st, info, _ = call("GET", B + "/admin/serverinfo", admin_token(B))
assert st == 200, st

AUTHENTICATORS = {"auth-cookie", "auth-spnego", "identity-provider-redirector", "idp-review-profile", "idp-create-user-if-unique",
    "idp-detect-existing-broker-user", "idp-auto-link", "idp-confirm-link", "idp-email-verification", "idp-username-password-form",
    "auth-username-password-form", "auth-username-form", "auth-password-form", "auth-otp-form", "direct-grant-validate-username",
    "direct-grant-validate-password", "direct-grant-validate-otp", "reset-credentials-choose-user", "reset-credential-email",
    "reset-password", "reset-otp", "webauthn-authenticator", "webauthn-authenticator-passwordless", "deny-access-authenticator",
    "allow-access-authenticator", "conditional-user-configured", "conditional-user-role", "conditional-user-attribute"}
CLIENT_AUTHENTICATORS = {"client-secret", "client-jwt", "client-secret-jwt"}
MAPPERS = {"oidc-usermodel-property-mapper", "oidc-usermodel-attribute-mapper", "oidc-full-name-mapper", "oidc-address-mapper",
    "oidc-usermodel-realm-role-mapper", "oidc-usermodel-client-role-mapper", "oidc-group-membership-mapper", "oidc-audience-mapper",
    "oidc-audience-resolve-mapper", "oidc-hardcoded-claim-mapper", "oidc-hardcoded-role-mapper", "oidc-role-name-mapper",
    "oidc-allowed-origins-mapper", "oidc-sub-mapper", "oidc-acr-mapper", "oidc-usersessionmodel-note-mapper"}
SAML_MAPPERS = {"saml-user-attribute-nameid-mapper", "saml-audience-resolve-mapper", "saml-user-session-note-mapper",
    "saml-audience-mapper", "saml-group-membership-mapper", "saml-role-name-mapper", "saml-user-property-mapper",
    "saml-role-list-mapper", "saml-hardcode-attribute-mapper", "saml-user-attribute-mapper", "saml-hardcode-role-mapper"}
SAML_INSTALLATIONS = {"saml-sp-descriptor"}
KEYS = {"rsa-generated", "rsa", "ecdsa-generated", "hmac-generated"}
IDPS = {"oidc", "keycloak-oidc", "github", "facebook", "google", "microsoft", "gitlab"}
LDAP_MAPPERS = {"user-attribute-ldap-mapper", "full-name-ldap-mapper", "group-ldap-mapper", "role-ldap-mapper",
    "hardcoded-ldap-role-mapper", "hardcoded-ldap-group-mapper", "hardcoded-ldap-attribute-mapper", "certificate-ldap-mapper",
    "msad-user-account-control-mapper", "msad-lds-user-account-control-mapper", "kerberos-principal-attribute-mapper"}
POLICIES = {"length", "maxLength", "digits", "lowerCase", "upperCase", "specialChars", "notUsername", "notEmail",
    "notContainsUsername", "regexPattern", "passwordHistory", "forceExpiredPasswordChange", "hashAlgorithm", "hashIterations"}
# features of the console gocloak does not implement (yet)
DISABLED = {"ORGANIZATION", "IMPERSONATION", "CIBA", "KERBEROS", "STEP_UP_AUTHENTICATION",
    "CLIENT_POLICIES", "ADMIN_FINE_GRAINED_AUTHZ", "TOKEN_EXCHANGE", "DPOP", "PASSKEYS", "RECOVERY_CODES", "DOCKER", "SCRIPTS"}

out = {k: v for k, v in info.items() if k not in ("systemInfo", "memoryInfo", "themes")}
for f in out["features"]:
    if f["name"] in DISABLED:
        f["enabled"] = False
out["profileInfo"]["disabledFeatures"] = sorted({f["name"] for f in out["features"] if not f["enabled"]})
out["protocolMapperTypes"] = {"openid-connect": [m for m in info["protocolMapperTypes"]["openid-connect"] if m["id"] in MAPPERS],
    "saml": [m for m in info["protocolMapperTypes"]["saml"] if m["id"] in SAML_MAPPERS]}
out["builtinProtocolMappers"] = {"openid-connect": [m for m in info["builtinProtocolMappers"]["openid-connect"] if m["protocolMapper"] in MAPPERS],
    "saml": [m for m in info["builtinProtocolMappers"]["saml"] if m["protocolMapper"] in SAML_MAPPERS]}
out["clientInstallations"] = {"openid-connect": [c for c in info["clientInstallations"]["openid-connect"] if c["id"] == "keycloak-oidc-keycloak-json"],
    "saml": [c for c in info["clientInstallations"]["saml"] if c["id"] in SAML_INSTALLATIONS]}
keep = {"org.keycloak.authentication.Authenticator": AUTHENTICATORS, "org.keycloak.authentication.ClientAuthenticator": CLIENT_AUTHENTICATORS,
    "org.keycloak.broker.provider.IdentityProvider": IDPS, "org.keycloak.broker.social.SocialIdentityProvider": IDPS,
    "org.keycloak.keys.KeyProvider": KEYS, "org.keycloak.protocol.ProtocolMapper": MAPPERS | SAML_MAPPERS,
    "org.keycloak.storage.UserStorageProvider": {"ldap"}, "org.keycloak.storage.ldap.mappers.LDAPStorageMapper": LDAP_MAPPERS}
ct = {}
for typ, comps in info["componentTypes"].items():
    if "clientpolicy" in typ:
        continue
    ct[typ] = [c for c in comps if typ not in keep or c["id"] in keep[typ]]
out["componentTypes"] = ct
out["identityProviders"] = [p for p in info["identityProviders"] if p["id"] in IDPS]
out["socialProviders"] = [p for p in info["socialProviders"] if p["id"] in IDPS]
out["passwordPolicies"] = [p for p in info["passwordPolicies"] if p["id"] in POLICIES]
lp = out["providers"]["login-protocol"]["providers"]
out["providers"]["login-protocol"]["providers"] = {k: v for k, v in lp.items() if k in ("openid-connect", "saml")}
path = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "admin", "serverinfo.json")
json.dump(out, open(path, "w"), indent=1, sort_keys=True, ensure_ascii=False)
print("wrote", path, os.path.getsize(path))
