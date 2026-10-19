# gocloak roadmap

This plan covers the Keycloak features gocloak does not implement yet, in the
order we intend to build them. Each milestone lists its scope, the Keycloak API
surface to stay compatible with, design notes, and the acceptance criteria that
mark it done. Sizes are rough: S (days), M (1–2 weeks), L (3–4 weeks), XL (more).

Guiding rules for every milestone:

- **Keycloak compatibility first.** Same URLs, JSON representations, error
  shapes and token claims, so existing clients (keycloak-js, kcadm.sh, the
  Nerzal/gocloak Go client, Spring/Quarkus adapters) work unchanged.
- **Realm import/export must round-trip** every entity a milestone adds.
- **End-to-end tests over HTTP** for every new flow, like `internal/server/server_test.go`.
- **No unauthenticated state growth**: anything created before login (auth
  sessions, action tokens, brute force counters) is bounded and expires.

## Current state (v0)

Done: OIDC core (auth code + PKCE, password, client credentials, refresh,
userinfo, introspection, revocation, logout, SSO cookie, CORS), admin REST for
realms / users / clients / roles / groups / role mappings / sessions, Keycloak
role-based admin authorization, realm import with Keycloak password hashes,
SQLite storage, CLI. See the README for details.

---

## M0 — Foundations (M) ✅ done

Everything after this builds on it.

- **CI**: GitHub Actions running `go vet`, `go test -race`, `gofmt` check, and
  the Docker build on every push and PR.
- **Versioned migrations**: replace the single `schema.sql` with numbered
  migrations and a `schema_migrations` table, so later milestones can alter
  tables of existing databases.
- **PostgreSQL support**: a second dialect next to SQLite (pgx driver), chosen
  with `--db sqlite|postgres` and `--db-url` (`KC_DB`, `KC_DB_URL`,
  `KC_DB_USERNAME`, `KC_DB_PASSWORD` like Keycloak). Keep SQL portable; isolate
  the few dialect differences (placeholders, upserts, booleans) in the store.
  CI runs the full test suite against both.
- **Realm export**: `gocloak export --realm X --file f.json [--users
  realm_file|skip]` and `POST /admin/realms/{realm}/partial-export`, producing
  JSON that Keycloak itself can import (and that gocloak re-imports identically).
- **Realm settings model**: an extensible place for the per-realm settings the
  next milestones add (password policy, brute force, SMTP, OTP policy, themes,
  events), stored as typed columns or a JSON attributes blob with typed accessors.

Acceptance: tests pass on SQLite and PostgreSQL in CI; a realm exported from
gocloak imports into Keycloak 26 and back without loss of supported fields.

## M1 — Client scopes and protocol mappers (L) ✅ done

The biggest compatibility gap today: real Keycloak setups customise tokens with
client scopes and mappers, and request custom scopes that gocloak ignores.

- **Client scopes** as entities: realm default/optional scopes, client
  default/optional scopes, `include.in.token.scope`, `display.on.consent.screen`.
  Provision Keycloak's built-ins per realm: `profile`, `email`, `roles`,
  `web-origins`, `acr`, `basic`, `address`, `phone`, `offline_access`,
  `microprofile-jwt`, `organization`.
- **Protocol mappers** on clients and client scopes, with the common types:
  user property, user attribute, full name, address, realm roles, client roles,
  group membership, audience, audience resolve, hardcoded claim, hardcoded role,
  role name mapper, allowed web origins, sub, acr. Each with Keycloak's config keys
  (`claim.name`, `jsonType.label`, `access.token.claim`, `id.token.claim`,
  `userinfo.token.claim`, `introspection.token.claim`, `multivalued`, ...).
- **Role scope mappings** (`/clients/{id}/scope-mappings`,
  `/client-scopes/{id}/scope-mappings`) so `fullScopeAllowed=false` behaves like
  Keycloak instead of "own roles only".
- Unknown scopes rejected with `invalid_scope`, as Keycloak does.
- Refactor token building into a mapper pipeline: the current hard-coded
  claims become the default mappers of the built-in scopes.
- Admin API: `/client-scopes`, `/default-default-client-scopes`,
  `/default-optional-client-scopes`, `/clients/{id}/default-client-scopes`,
  `/clients/{id}/optional-client-scopes`, `/protocol-mappers/...`,
  `/clients/{id}/evaluate-scopes/generate-example-access-token`.

Acceptance: a token issued by gocloak for an imported realm matches the token
Keycloak issues for the same realm/user/client, claim for claim (excluding
ids, timestamps and signatures). Write this as a golden-file test.

Done notes: golden files recorded from Keycloak 26.0.7 by
`scripts/compat/tokens.py` (`TestKeycloakCompatibility`). The `organization`
scope is left for when organizations exist. Found while comparing: Keycloak 26
drops user attributes that are not declared in its user profile; gocloak keeps
them. A declarative user profile is added to M3.

## M2 — Security hardening (M) ✅ done

- **Brute force detection**: per-user failure counting with Keycloak's settings
  (`bruteForceProtected`, `failureFactor`, `waitIncrementSeconds`,
  `maxFailureWaitSeconds`, `permanentLockout`, `quickLoginCheckMilliSeconds`...),
  applied to the login form and the password grant;
  `/attack-detection/brute-force/users[/{id}]` admin endpoints.
- **Password policy**: `length`, `maxLength`, `digits`, `lowerCase`,
  `upperCase`, `specialChars`, `notUsername`, `notEmail`, `passwordHistory`,
  `forceExpiredPasswordChange`, `hashAlgorithm`, `hashIterations`, `regexPattern`;
  enforced on admin reset, update-password and (later) registration, with
  Keycloak's error messages. Rehash on login when the policy's algorithm changes.
- **Events**: login events (`LOGIN`, `LOGIN_ERROR`, `CODE_TO_TOKEN`,
  `REFRESH_TOKEN`, `LOGOUT`, `CLIENT_LOGIN`, ...) and admin events, with
  `eventsEnabled`, `eventsExpiration`, `adminEventsEnabled`,
  `adminEventsDetailsEnabled`; `/events`, `/admin-events`, `/events/config`.
  A pluggable listener interface (log, database, webhook).
- **Offline tokens**: `offline_access` scope, offline sessions that survive
  logout, `offlineSessionIdleTimeout`, `/users/{id}/offline-sessions/{client}`.
- **Refresh token rotation**: `revokeRefreshToken` and `refreshTokenMaxReuse`.
- **Not-before / push revocation**: realm and client `notBefore`,
  `/push-revocation`.
- **JWT client authentication**: `client_secret_jwt` and `private_key_jwt`
  (client JWKS URL or uploaded certificate), plus `tls_client_auth` later.
- **Key management**: key providers as Keycloak components (`rsa-generated`,
  `rsa` with imported key, `hmac-generated`), active/passive/disabled keys,
  rotation without downtime, ES256/PS256 signature algorithms per client.
- **Rate limiting** on unauthenticated endpoints, and a review of all
  pre-login state for bounded growth.

Acceptance: a scripted password-guessing run is locked out per policy; offline
tokens keep working after SSO logout and stop after revocation; key rotation
keeps previously issued tokens verifiable.

Done notes: behaviour checked against Keycloak 26.0.7 (policy error bodies,
lockout responses, refresh/offline token claims, reuse errors) and recorded as
golden files. Not done: `tls_client_auth` (needs mTLS termination), AES and
RSA-OAEP keys (only used for encrypted tokens), `quickLoginCheck` with
millisecond-exact Keycloak timing beyond what the golden scenarios cover.

## M3 — Account lifecycle and MFA (L) ✅ done

- **Email**: SMTP settings per realm (`smtpServer`), templated emails (HTML +
  text), `/testSMTPConnection`.
- **Action tokens**: signed, single-use, expiring tokens behind
  `/login-actions/action-token`, the basis for the flows below.
- **Required actions**: `VERIFY_EMAIL`, `UPDATE_PROFILE`, `CONFIGURE_TOTP`,
  `TERMS_AND_CONDITIONS`, `UPDATE_EMAIL`, with the
  `/authentication/required-actions` admin API and default actions for new users.
- **Registration** (`registrationAllowed`, `registrationEmailAsUsername`,
  `verifyEmail`) and **forgot password** (`resetPasswordAllowed`).
- **Admin-triggered emails**: `PUT /users/{id}/execute-actions-email`,
  `/send-verify-email`.
- **OTP**: TOTP/HOTP credentials with the realm OTP policy (algorithm, digits,
  period, look-ahead), setup page with QR code, `CONFIGURE_TOTP`.
- **WebAuthn / passkeys**: registration and authentication (go-webauthn),
  WebAuthn policy, passwordless option.
- **Authentication flows (simplified)**: a small flow engine with Keycloak's
  executions and requirements (REQUIRED / ALTERNATIVE / CONDITIONAL / DISABLED)
  for the browser, direct grant, registration and reset credentials flows, and
  the `/authentication/flows` admin API for the supported authenticators. Full
  arbitrary flow editing is not a goal; importing a realm with unsupported
  authenticators must fail loudly rather than silently weaken login.
- **Remember me** and `KEYCLOAK_REMEMBER_ME`.
- **User profile**: declared attributes with validators and permissions
  (`/users/profile`), `unmanagedAttributePolicy`, as in Keycloak 24+.

Acceptance: a new user can register, verify email, set up TOTP and log in with
it; an admin can force a password reset by email; flows from a Keycloak export
using only supported authenticators behave the same.

Done notes: default user profile, required actions and flow trees, profile
validation errors and authentication API errors match Keycloak 26.0.7 (golden
files). Not done: reCAPTCHA, `delete_account`, `delete_credential`,
`update_user_locale` (accepted and skipped), the organization authenticators,
X.509 and Kerberos authenticators, configurable email templates (themes, M4).

## M4 — Login theming and account console (M) ✅ done

- **Theme system**: theme directories (`--themes-dir`) overriding the embedded
  login templates and CSS, `loginTheme`/`emailTheme` per realm, and message
  bundles with `ui_locales` / `KEYCLOAK_LOCALE` (start with en and vi).
- **Account console** at `/realms/{realm}/account`, server-rendered: profile,
  password, OTP/WebAuthn devices, sessions (sign out others), linked accounts,
  applications. Also the account REST API (`/realms/{realm}/account/...`) that
  keycloak-js based account UIs call.

Acceptance: a custom theme directory changes the login page without rebuilding;
a user can manage their own credentials and sessions.

Done notes: themes use Go templates rather than FreeMarker, so Keycloak's
`.ftl` templates do not apply; their message bundles and resources do.
Linked accounts in the console come with identity brokering (M5).

## M5 — Identity brokering (L) ✅ done

- **Identity providers**: generic OpenID Connect and OAuth 2.0, plus presets for
  Google, GitHub, Microsoft, GitLab, Facebook, Apple. `/identity-provider/instances`
  admin API, IdP buttons on the login page, `kc_idp_hint`.
- **First broker login**: create the user, or link to an existing account after
  re-authentication / email verification, matching Keycloak's default flow.
- **Federated identities**: `/users/{id}/federated-identity`, linking from the
  account console, token storage (`storeToken`) and `/broker/{alias}/token`.
- **IdP mappers**: attribute importer, hardcoded role/attribute, username template.
- Back-channel and front-channel logout towards the IdP.

Acceptance: log in with an external OIDC provider (tested against a second
gocloak instance acting as IdP), link an existing account, and get the mapped
roles in the token.

Done notes: the admin representations (providers, mappers, mapper types,
federated identities) and the login page links match Keycloak 26.0.7. Beyond
the plan: the `oauth2` generic provider, `idp-auto-link` and
`idp-detect-existing-broker-user`, the advanced claim to role / group and
session note mappers, client initiated account linking (`/broker/{alias}/link`),
`/identity-provider/import-config`, and logout of the provider session found
from an `id_token_hint` without SSO cookie. Social presets other than GitHub
are tested only through the generic code paths, not against the real services.
Not done: SAML providers (M9), token exchange with external tokens (M10), the
organization authenticators.

## M6 — LDAP user federation (L) ✅ done

- **LDAP provider** (go-ldap) as a Keycloak component: connection settings,
  bind credentials, `editMode` READ_ONLY / WRITABLE / UNSYNCED, import vs
  no-import mode, `/user-storage/{id}/sync` full and changed-users sync, periodic
  sync.
- **LDAP mappers**: user attribute, full name, group, role, hardcoded role,
  certificate.
- Password validation through LDAP bind; password changes written back in
  WRITABLE mode.
- Kerberos/SPNEGO is out of scope unless asked for.

Acceptance: against an OpenLDAP container in CI, users and groups sync, log in
with their LDAP password, and changes flow back in WRITABLE mode.

Done notes: the provider and mapper components (defaults per vendor, rdn and
edit mode, validation messages), the connection test, sync results and the
imported users match Keycloak 26.0.7 run against the same directory. The LDAP
tests run on an in-memory directory (`internal/ldaptest`) and, in CI, on
OpenLDAP. Differences: Keycloak reads always-read attributes and READ_ONLY /
LDAP_ONLY group and role memberships from LDAP on every access, gocloak
refreshes them at login and at synchronization; with `importEnabled=false`
users are still stored locally (with Keycloak's `f:<provider>:<id>` ids).
Active Directory specifics (objectGUID, unicodePwd, userAccountControl) are
implemented but only tested against Keycloak's behaviour on paper. Not done:
Kerberos, `ldap-server-capabilities`, the MSAD LDS mapper beyond enabled state.

## M7 — Admin console (L) ✅ done

Decision to take at the start of the milestone:

1. **Serve Keycloak's own admin console** (`keycloak/keycloak-admin-ui`, Apache
   2.0) against gocloak's API. Needs the endpoints it calls beyond the admin REST
   API (`/admin/serverinfo`, `/admin/realms/{realm}/ui-ext/...`, whoami,
   `security-admin-console` client, admin console config). Most compatible and
   least UI code, but couples us to its release cadence and to many endpoints.
2. **Own server-rendered console** (Go templates + htmx) covering only what
   gocloak supports. Simpler, but a second UI to maintain.

Prototype option 1 first; fall back to option 2 if the required API surface is
too large. Either way, the console authenticates through the
`security-admin-console` public client with PKCE.

Acceptance: an admin can manage realms, users, clients, roles, groups and
sessions entirely from the browser.

Done notes: option 1. Keycloak's admin console 26.0.7 runs unchanged against
gocloak; its files are read from the keycloak-admin-ui and keycloak-themes jars
(downloaded from Maven Central, bundled in the Docker image, not in the
repository). A headless browser walkthrough (63 pages and create / update /
delete of realms, users, passwords, clients, roles, groups, role mappings,
identity providers) sends the same requests and gets the same results as
against Keycloak 26.0.7. `/admin/serverinfo` is Keycloak's catalog reduced to
the providers gocloak implements (`scripts/compat/serverinfo.py`), and features
gocloak lacks (organizations, authorization, device flow, CIBA, PAR, client
policies...) are disabled so the console hides them. Not done: realm
localization texts (empty), partial import / export from the console, client
installation formats, impersonation.

## M8 — Authorization services (XL) ✅ done

Keycloak's fine-grained authorization (UMA 2.0):

- Resource servers on clients (`authorizationServicesEnabled`), resources,
  scopes, policies (role, user, group, client, client scope, time, regex,
  aggregated; JavaScript policies are out of scope), permissions (resource and
  scope based), decision strategies and policy enforcement modes.
- Token endpoint grant `urn:ietf:params:oauth:grant-type:uma-ticket` (RPTs,
  `response_mode=decision|permissions`), permission tickets, the Protection API
  (`/authz/protection/resource_set`, `/permission`), and
  `/clients/{id}/authz/resource-server/...` admin API including policy evaluation.
- Admin fine-grained permissions (users/clients/groups) after the above.

Acceptance: Keycloak's authorization quickstarts (photoz-style) pass against gocloak.

Done notes: representations, error responses, evaluation results and RPTs
were compared with Keycloak 26.0.7 on the same resource server; a photoz-like
scenario (protection API registration, owner managed albums, typed and scope
permissions, tickets with submitted and approved requests, RPT upgrades) runs
in the tests. JavaScript policies other than Keycloak's default "grant" policy
are rejected, as gocloak runs no scripts. Not done: admin fine-grained
permissions (users / clients / groups), the user-managed access policy API
(`/authz/protection/uma-policy`) and the account console "My resources" page,
pushed claims (`claim_token`). The order of evaluation results differs from
Keycloak's, which does not guarantee one.

## M9 — SAML 2.0 (XL) ✅ done

- SAML IdP: descriptor endpoint, SP-initiated and IdP-initiated SSO, Redirect
  and POST bindings, signed responses/assertions, optional encryption, Single
  Logout, NameID formats.
- SAML clients and SAML protocol mappers; SAML as a brokering provider later.
- Use a well-reviewed XML signature library; fuzz the parser.

Acceptance: login works for a reference SP (e.g. crewjam/saml sample and a
SimpleSAMLphp SP) in CI.

Done notes: signatures use goxmldsig (signing works on a copy, since its
canonicalization mutates the document), incoming documents go through
xml-roundtrip-validator and only the signed content is trusted; the parsers
are fuzzed. Responses, assertions, logout messages, error pages and the
descriptor were compared with Keycloak 26.0.7 for the same client
configurations, and the SAML client pages of the admin console were walked
through on both. The reference service providers are crewjam/saml (in the Go
tests) and Keycloak itself (`scripts/compat/saml_sp.py`, the `saml-interop` CI
job: login through Keycloak's SAML broker with signed requests, signed or
encrypted assertions, both bindings, and SP initiated logout); SimpleSAMLphp
was replaced by Keycloak, a stricter SP. Differences: the persistent NameID is
generated per login unless the user has a `saml.persistent.name.id.for.*`
attribute, as in Keycloak; when a client has its own role list mapper only that
one applies (Keycloak picks one of them at random). Not done: SAML identity
brokering (gocloak as SP), the artifact binding, ECP (the `saml ecp` flow of
Keycloak exports is accepted but not run), `keycloak-saml` and
`mod-auth-mellon` adapter downloads.

## M10 — Additional OAuth specs (M, can be split)

Device authorization grant, token exchange (RFC 8693, internal-to-internal
first), Pushed Authorization Requests, request objects (`request`,
`request_uri`), consent screen and stored consents, DPoP, CIBA, front-channel
and back-channel logout to clients (`frontchannelLogout`,
`backchannel.logout.url`), dynamic client registration, lightweight access
tokens (`client.use.lightweight.access.token.enabled`, which Keycloak 26 sets on
`admin-cli`).

Acceptance: the OpenID Foundation conformance suite passes the "Basic OP",
"Config OP" and "Form Post OP" profiles.

## M11 — Operations and scale (M)

- **Clustering**: stateless nodes over a shared PostgreSQL database; cross-node
  invalidation of the key and realm caches; optional Redis for sessions if the
  database becomes the bottleneck.
- **Observability**: Prometheus `/metrics` (Keycloak-like metric names where
  they exist), OpenTelemetry tracing, JSON logs, a separate management port
  (`--http-management-port`, default 9000) for health and metrics.
- **Performance**: cache effective roles and realm/client lookups per request,
  benchmark token issuance and the login flow, load test with k6.
- **Packaging**: release binaries and multi-arch images via GoReleaser, Helm chart.

Acceptance: three nodes behind a load balancer serve logins and refreshes
without sticky sessions; p99 token endpoint latency is documented.

---

## Known technical debt in v0

To fix opportunistically, at the latest in the milestone noted:

- `EffectiveRoles` loads all roles and composite edges of a realm on every
  call, and admin requests recompute the caller's roles each time (M11).
- Admin API has no CORS support for browser-based tools (M7).
- Sessions and auth codes live in the database; fine for one node, revisit for
  clustering (M11).
- Admin error messages only partly match Keycloak's wording (ongoing).

## Out of scope

Keycloak's Java SPI and script providers, JavaScript authorization policies,
Kerberos (unless requested), Infinispan-specific features, legacy `/auth` URL
prefix (can be added as a redirect if needed).
