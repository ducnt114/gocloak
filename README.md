# gocloak

An identity and access management server written in Go, modelled on
[Keycloak](https://www.keycloak.org). It keeps Keycloak's URL layout, JSON
representations, role model and token format, so applications using standard
OIDC and scripts using the core admin endpoints can switch with little or no change.

It is a single static binary: no JVM. It runs on an embedded SQLite database
out of the box, or on PostgreSQL for production.

> Status: early. The core OpenID Connect flows and the admin REST API for
> realms, users, clients, roles and groups are implemented and tested. Many
> Keycloak features are not (see [Not implemented yet](#not-implemented-yet)).

## Quick start

```sh
go build -o gocloak ./cmd/gocloak

KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  ./gocloak start-dev
```

The admin console needs Keycloak's console files, which are not part of the binary:

```sh
./gocloak download-admin-console --dir admin-console   # from Maven Central
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  ./gocloak start-dev --admin-console-dir admin-console
# then open http://localhost:8080/admin/
```

Or through the admin REST API:

```sh
# admin token from the master realm
TOKEN=$(curl -s -d grant_type=password -d client_id=admin-cli \
  -d username=admin -d password=admin \
  http://localhost:8080/realms/master/protocol/openid-connect/token | jq -r .access_token)

# create a realm, a client and a user
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"realm":"demo","enabled":true}' http://localhost:8080/admin/realms

curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"clientId":"web","secret":"s3cret","redirectUris":["http://localhost:3000/*"],"directAccessGrantsEnabled":true}' \
  http://localhost:8080/admin/realms/demo/clients

curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"alice","enabled":true,"credentials":[{"type":"password","value":"alice","temporary":false}]}' \
  http://localhost:8080/admin/realms/demo/users

# discovery document for applications
curl http://localhost:8080/realms/demo/.well-known/openid-configuration
```

With Docker (the image includes the admin console):

```sh
docker build -t gocloak .
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v gocloak-data:/data gocloak start-dev
```

Releases publish binaries for Linux, macOS and Windows (amd64 and arm64) on
the GitHub releases page, and a multi-arch image:

```sh
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v gocloak-data:/data ghcr.io/ducnt114/gocloak start-dev
```

On Kubernetes, with the Helm chart (`charts/gocloak`, also published as
`oci://ghcr.io/ducnt114/charts/gocloak`):

```sh
# one node on SQLite
helm install sso oci://ghcr.io/ducnt114/charts/gocloak --set hostname=https://sso.example.com

# three nodes on PostgreSQL
helm install sso oci://ghcr.io/ducnt114/charts/gocloak --set hostname=https://sso.example.com \
  --set replicaCount=3 --set database.vendor=postgres \
  --set database.url=postgres://db.example.com/gocloak --set database.username=gocloak \
  --set database.existingSecret=gocloak-db
```

See `charts/gocloak/values.yaml` for the settings (ingress, metrics and
ServiceMonitor, tracing, realm import, resources).

### Running a cluster

Nodes on the same PostgreSQL database form a cluster: they keep no state of
their own, so a load balancer needs no sticky sessions. Each node caches
signing keys and realm configuration, and tells the others about changes
through PostgreSQL `LISTEN`/`NOTIFY`. Periodic jobs (expired session cleanup,
LDAP synchronization) run on one node at a time under advisory locks.
Measurements of a three-node cluster are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Commands

| Command | Description |
| --- | --- |
| `gocloak start-dev` | Development mode: HTTP, hostname taken from each request, debug logs. |
| `gocloak start --hostname https://sso.example.com` | Production mode; `--hostname` is required (or `--hostname-strict=false`). |
| `gocloak import --file realm.json` / `--dir dir/` | Import Keycloak realm exports and exit. Existing realms are skipped. |
| `gocloak export --realm demo --file demo.json` / `--dir dir/` | Export one or all realms (with users and secrets; `--users skip` leaves users out) and exit. |
| `gocloak bootstrap-admin --username admin --password ...` | Create or reset a master realm admin and exit. |

Main options (flag / environment variable):

| Flag | Env | Default |
| --- | --- | --- |
| `--db` | `KC_DB` | `sqlite` (or `postgres`) |
| `--db-url` | `KC_DB_URL` | `data/gocloak.db` for SQLite; for PostgreSQL `postgres://host:5432/db` or Keycloak's `jdbc:postgresql://host:5432/db` |
| `--db-username`, `--db-password` | `KC_DB_USERNAME`, `KC_DB_PASSWORD` | PostgreSQL credentials |
| `--http-host`, `--http-port` | `KC_HTTP_HOST`, `KC_HTTP_PORT` | `0.0.0.0`, `8080` |
| `--https-certificate-file`, `--https-certificate-key-file`, `--https-port` | `KC_HTTPS_CERTIFICATE_FILE`, `KC_HTTPS_CERTIFICATE_KEY_FILE`, `KC_HTTPS_PORT` | HTTPS off, `8443` |
| `--hostname` | `KC_HOSTNAME` | derived from the request |
| `--proxy-headers xforwarded` | `KC_PROXY_HEADERS` | do not trust `X-Forwarded-*` |
| `--import-dir` | `GOCLOAK_IMPORT_DIR` | none |
| `--rate-limit`, `--rate-burst` | `GOCLOAK_RATE_LIMIT`, `GOCLOAK_RATE_BURST` | 100 requests/s per client IP, burst 200 (`0` disables); behind a proxy use `--proxy-headers` so the client IP is used |
| `--log-level`, `--log-console-output` | `KC_LOG_LEVEL`, `KC_LOG_CONSOLE_OUTPUT` | `info` (`debug` in dev mode), `default` (or `json`) |
| `--health-enabled`, `--metrics-enabled`, `--http-management-port` | `KC_HEALTH_ENABLED`, `KC_METRICS_ENABLED`, `KC_HTTP_MANAGEMENT_PORT` | off, off, `9000`: health checks and Prometheus metrics (`/metrics`, Keycloak's `http_server_requests_seconds` and `keycloak_user_events_total`) on the management port; `--http-metrics-histograms-enabled` adds buckets. `/health` stays on the main port too |
| `--tracing-enabled`, `--tracing-endpoint`, `--tracing-service-name`, `--tracing-sampler-ratio`, `--tracing-resource-attributes` | `KC_TRACING_*` | off, `http://localhost:4318`, `gocloak`, `1.0`: a span per request exported with OTLP over HTTP (protobuf), continuing W3C `traceparent` |
| `--ciba-auth-channel-uri` | `GOCLOAK_CIBA_AUTH_CHANNEL_URI` | none: where CIBA authentication requests are posted |
| `--themes-dir`, `--theme-cache` | `GOCLOAK_THEMES_DIR` | no custom themes; cache off in dev mode |
| — | `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD` (or legacy `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`) | admin created with the master realm on first start |

## What is implemented

**OpenID Connect / OAuth 2.0** (`/realms/{realm}/protocol/openid-connect/...`)

- Discovery (`/.well-known/openid-configuration`), JWKS (`/certs`), realm info (`/realms/{realm}`)
- Authorization code flow with login page, PKCE (`plain`, `S256`, and enforcement via the
  `pkce.code.challenge.method` client attribute), `response_mode` query / fragment / form_post,
  `prompt=none|login`, `max_age`, `login_hint`, `iss` in the response
- SSO across clients through a signed `KEYCLOAK_IDENTITY` cookie
- Grants: `authorization_code`, `password`, `client_credentials` (service accounts), `refresh_token`
- Client authentication: `client_secret_basic`, `client_secret_post`, `client_secret_jwt` and
  `private_key_jwt` (client JWKS URL, inline JWKS or certificate, replay protection); public and
  bearer-only clients
- Offline tokens (`offline_access`) backed by offline sessions that survive logout, refresh token
  rotation (`revokeRefreshToken`, `refreshTokenMaxReuse`), realm / client / user not-before policies
- Signing keys as Keycloak key providers: `rsa-generated`, `rsa` (imported), `ecdsa-generated`,
  `hmac-generated`; RS256/384/512, PS256/384/512, ES256/384/512 per realm or per client
  (`access.token.signed.response.alg`, `id.token.signed.response.alg`), HS512 refresh tokens,
  key rotation with passive keys, certificates (`x5c`) in the JWKS
- Brute force detection (temporary and permanent lockout, `MULTIPLE` / `LINEAR` strategies) and
  password policies (`length`, `maxLength`, `digits`, `lowerCase`, `upperCase`, `specialChars`,
  `notUsername`, `notEmail`, `notContainsUsername`, `regexPattern`, `passwordHistory`,
  `forceExpiredPasswordChange`, `hashAlgorithm`, `hashIterations`) with Keycloak's error messages
- Login and admin events with Keycloak's event types and details, the `jboss-logging` listener,
  expiration, and per IP rate limiting of `/realms` and `/admin`
- `userinfo`, token introspection, token revocation (RFC 7009)
- RP-initiated logout (`id_token_hint`, `post_logout_redirect_uri`, confirmation page) and
  Keycloak's back-channel logout with a refresh token; OpenID Connect front-channel logout
  (`frontchannelLogout`, `frontchannel.logout.url`) and back-channel logout tokens
  (`backchannel.logout.url`) sent to clients when sessions end
- Consent: `consentRequired` clients, the "Grant Access" page, stored consents (admin and account
  APIs, realm export), `prompt=consent`
- Pushed Authorization Requests (RFC 9126, `require.pushed.authorization.requests`) and request
  objects (`request`, registered `request_uri`; unsigned, HMAC or client keys)
- Device authorization grant (RFC 8628) with the `/realms/{realm}/device` page; CIBA (poll and ping)
  through Keycloak's HTTP authentication channel (`--ciba-auth-channel-uri`)
- Token exchange between clients (RFC 8693, Keycloak's standard token exchange:
  `standard.token.exchange.enabled`, audiences, refresh tokens of the same session)
- DPoP (RFC 9449): proofs at the token endpoint, `cnf.jkt` bound access tokens and public clients'
  refresh tokens, `dpop.bound.access.tokens`, DPoP-bound tokens checked at userinfo and the admin
  and account APIs
- Lightweight access tokens (`client.use.lightweight.access.token.enabled`, on for `admin-cli`
  and the console as in Keycloak 26), expanded by introspection
- Dynamic client registration (RFC 7591/7592 at `/clients-registrations/openid-connect`, and
  Keycloak's `default` provider), initial access tokens, registration access tokens and client
  registration policies
- CORS from the client's web origins (including `+`)
- Authentication flows as in Keycloak: the built-in browser, direct grant, registration, reset
  credentials and client flows, custom flows and per-client bindings, executions with REQUIRED /
  ALTERNATIVE / CONDITIONAL / DISABLED, and the authenticators cookie, username password form,
  username form, password form, OTP form, WebAuthn (two-factor and passwordless passkeys),
  conditional user configured / role / attribute, allow / deny access, direct grant username /
  password / OTP, and the reset credentials steps
- Required actions: `UPDATE_PASSWORD`, `UPDATE_PROFILE`, `VERIFY_PROFILE`, `VERIFY_EMAIL`,
  `CONFIGURE_TOTP` (QR code), `TERMS_AND_CONDITIONS`, `UPDATE_EMAIL`, `webauthn-register`,
  `webauthn-register-passwordless`, default actions for new users and `kc_action`
- Self-registration, forgot password by email, email verification, admin requested actions by
  email (single-use action tokens), remember me
- OTP (TOTP / HOTP) with the realm OTP policy and code reuse protection
- Declarative user profile: Keycloak's default attributes and validators (`length`, `email`,
  `pattern`, `username-prohibited-characters`, `person-name-prohibited-characters`, `integer`,
  `double`, `uri`, `options`, `local-date`, `multivalued`), required attributes per context,
  permissions and `unmanagedAttributePolicy`
- Emails over SMTP (SSL / STARTTLS / authentication) with Keycloak's messages

**Identity brokering** (`/realms/{realm}/broker/{alias}/...`)

- Identity providers: generic OpenID Connect (`oidc`, `keycloak-oidc`) and OAuth 2.0 (`oauth2`),
  and the Google, GitHub (and Enterprise), Microsoft, GitLab, Facebook and Apple presets; client
  authentication `client_secret_post` / `basic` / `jwt` and `private_key_jwt`, PKCE, ID token
  validation with the provider's JWKS or a configured key, userinfo, stored tokens
- Provider buttons on the login page, `kc_idp_hint` and the `identity-provider-redirector`
  default provider, link-only and hidden providers
- The first broker login flow: review profile, create the user if unique, or confirm and link an
  existing account after email verification or re-authentication (with OTP); post broker login
  flows; `trustEmail`, `addReadTokenRoleOnCreate`, sync modes `IMPORT` / `LEGACY` / `FORCE`
- Mappers: attribute importer (claims and social JSON fields), username template, hardcoded
  attribute / role / group / session attribute, claim to role, advanced claim to role / group,
  session notes
- Federated identities: account linking from the account console and from applications
  (`/broker/{alias}/link`), unlinking, stored provider tokens at `/broker/{alias}/token`
  (`broker/read-token` role), front-channel and back-channel logout at the provider

**User federation (LDAP)**

- LDAP user storage providers as Keycloak components: vendors (other, AD, RHDS...), simple
  bind or anonymous, StartTLS and `ldaps://`, users DN with one level or subtree search, custom
  user filters, pagination, and the default mappers Keycloak creates
- Users found and imported at login (username or email), passwords checked with an LDAP bind;
  `editMode` READ_ONLY (mapped attributes read-only), WRITABLE (profile, password, enabled
  state and deletions written to LDAP, `syncRegistrations` for new users) and UNSYNCED
- Full and changed-users synchronization (`/user-storage/{id}/sync`), periodic sync
  (`fullSyncPeriod`, `changedSyncPeriod`), removal of users deleted in LDAP, remove / unlink
  imported users, `testLDAPConnection`
- Mappers: user attribute, full name, certificate, hardcoded attribute / role / group, MSAD
  account controls, and group and role mappers (DN or UID memberships, group inheritance,
  READ_ONLY / LDAP_ONLY / IMPORT modes, synchronization in both directions)

**Authorization services (UMA 2.0)**

- Resource servers on confidential clients (`authorizationServicesEnabled`), with Keycloak's
  default resource, policy and permission; resources (types, URIs, owners, owner managed access,
  attributes), scopes, policies (role, user, group, client, client scope, time, regex, aggregated,
  and the default JavaScript policy), resource and scope based permissions, decision strategies,
  positive / negative logic and the ENFORCING / PERMISSIVE / DISABLED enforcement modes
- The `urn:ietf:params:oauth:grant-type:uma-ticket` grant: RPTs with an `authorization` claim,
  `response_mode=decision|permissions`, permission tickets, `submit_request`, RPT upgrades,
  `response_include_resource_name` and `response_permissions_limit`
- The protection API for resource servers (`/authz/protection/resource_set`, `/permission`,
  `/permission/ticket`, with the `uma_protection` role) and `/.well-known/uma2-configuration`
- Admin API `/clients/{id}/authz/resource-server/...`: resources, scopes, policies and
  permissions (generic and typed), providers, associated / dependent policies, policy evaluation,
  settings export and import; authorization settings in realm exports; the admin console's
  Authorization tabs

**SAML 2.0 identity provider**

- SAML clients (`protocol: saml`) with Keycloak's defaults and attributes, the `role_list` client
  scope, IdP metadata at `/realms/{realm}/protocol/saml/descriptor`, the client description
  converter (import a client from SP metadata) and the `saml-sp-descriptor` installation
- SP initiated login (`AuthnRequest`) over the HTTP-Redirect and HTTP-POST bindings, IdP initiated
  login (`/protocol/saml/clients/{saml_idp_initiated_sso_url_name}`), `ForceAuthn`, `IsPassive`,
  the SSO session shared with OIDC clients
- Request signatures checked against the client certificate (query string or XML signature);
  responses and/or assertions signed with the realm RSA key (RSA-SHA1/256/512, exclusive or
  inclusive canonicalization); encrypted assertions (AES-CBC/GCM, RSA-OAEP with SHA-1/256/512)
- NameID formats unspecified (username), email, persistent and transient, and the NameID mapper
- SAML mappers: user property, user attribute, role list, group membership, hardcoded attribute
  and role, role name, user session note, audience and audience resolve
- Single Logout: `LogoutRequest` from service providers (front-channel through the browser to the
  other SAML clients of the session, back-channel with the POST or SOAP binding), and SAML
  logouts when the session ends through the OIDC logout endpoint, the account console or an
  administrator
- Checked against Keycloak 26.0.7 (same documents for the same configuration) and with
  Keycloak as the service provider (`scripts/compat/saml_sp.py`, run in CI); crewjam/saml is the
  service provider of the tests. Incoming XML is checked with xml-roundtrip-validator and fuzzed.

**Themes, languages and account console**

- Login, email and account themes: built-in theme embedded in the binary, custom themes from
  `--themes-dir` (`<theme>/<type>/theme.properties` with `parent` and `styles`, Go templates
  overriding pages, `messages/messages_<locale>.properties` in Keycloak's format, static
  `resources/` served under `/resources/<theme>/<type>/`), per realm `loginTheme`, `emailTheme`
  and `accountTheme`
- Internationalization with Keycloak's message keys: English and Vietnamese built in, locale from
  `kc_locale`, `ui_locales`, the `KEYCLOAK_LOCALE` cookie, the user's `locale` attribute or
  `Accept-Language`, a language selector on login pages, emails in the user's language
- Account console at `/realms/{realm}/account`: personal info (user profile), account security
  (password, OTP, security keys and passkeys through application initiated actions), device
  activity with sign out, linked accounts, applications with offline access revocation, groups
- Account REST API on the same paths (`Accept: application/json` or a bearer token): account,
  sessions and devices, credentials and labels, applications and consents, groups, linked accounts
- Client scopes and protocol mappers, as in Keycloak: the built-in scopes (`profile`, `email`,
  `roles`, `web-origins`, `acr`, `basic`, `address`, `phone`, `offline_access`, `microprofile-jwt`),
  default and optional scopes per realm and client, `invalid_scope` for unknown scopes, and
  mapper types for user properties and attributes, full name, address, realm / client roles,
  group membership, audience, audience resolve, hardcoded claim / role, role name, allowed
  origins, sub, acr and session notes
- Role scope mappings for clients without full scope allowed
- Tokens checked claim by claim against a real Keycloak 26 (see [Compatibility](#compatibility))

**Admin console**

- Keycloak's own admin console (keycloak-admin-ui 26.0.7, Apache License 2.0) served at
  `/admin/{realm}/console/`, read from the Keycloak jars (`gocloak download-admin-console`,
  `--admin-console-dir`); the Docker image includes them
- The endpoints it needs beyond the admin REST API: `/admin/serverinfo` (Keycloak's provider
  catalog reduced to what gocloak supports), `whoami`, the `ui-ext` extensions (realm names,
  sessions, brute force users, flows, required actions, available / effective roles, realm and
  user profile update), translations under `/resources/{realm}/admin/{locale}`, the
  `security-admin-console` client of every realm, and the keycloak-js iframes (third-party
  cookie check, login status iframe with the `KEYCLOAK_SESSION` cookie)
- Realms, users (credentials, role mappings, groups, sessions), clients, roles, groups, client
  scopes, identity providers, user federation, authentication flows, events and realm settings
  are managed from the console

**Admin REST API** (`/admin/realms/...`, Keycloak paths and JSON)

- Realms: list, create (including full realm import with nested roles, clients, groups, users),
  get, partial update, delete, `logout-all`, `keys`, `partial-export`, `push-revocation`,
  `components` (key providers), `events`, `events/config`, `admin-events`,
  `attack-detection/brute-force`
- Users: search (`search`, `username`, `email`, `firstName`, `lastName`, `exact`, `enabled`,
  `q` attribute queries, `briefRepresentation`, `first`, `max`), count, CRUD with partial updates, `reset-password`, credentials, sessions,
  logout, group membership, role mappings (realm, client, composite, available), offline sessions,
  consents (offline tokens)
- Authentication: flows (list, create, copy, delete), executions (add, sub flows, requirement,
  priority, configs), authenticator / form / client authenticator providers, required actions
  (list, update, priority, register)
- User profile: `users/profile`, `users/profile/metadata`, `userProfileMetadata` on users;
  `execute-actions-email`, `send-verify-email`, `testSMTPConnection`, credential labels
- Clients: search, CRUD, client secret get / regenerate, service account user, user sessions,
  client roles, protocol mappers, default / optional client scopes, scope mappings,
  `evaluate-scopes` (example access token, ID token, userinfo, applied mappers), certificates,
  installation providers (`keycloak-oidc-keycloak-json`, `saml-sp-descriptor`) and
  `client-description-converter`
- Client scopes: CRUD, protocol mappers, scope mappings, realm default / optional scopes
- Roles: realm and client roles CRUD, composites, users in role, `roles-by-id`
- Groups: tree listing, count, `group-by-path`, CRUD, children, members, role mappings, default
  groups
- Identity providers: `identity-provider/instances` CRUD, mappers, `mapper-types`,
  `providers/{id}`, `import-config`; users' `federated-identity` links and the `idpAlias` /
  `idpUserId` user search
- Authorization exactly by Keycloak's roles: master `admin` (all realms), master `create-realm`,
  and `realm-management` client roles (`realm-admin`, `manage-users`, `view-users`,
  `manage-clients`, `view-clients`, `manage-realm`, `view-realm`, `query-*`, `create-client`).
  Admins cannot grant admin roles they do not hold themselves.

**Keycloak compatibility details**

- New realms get the same built-ins as Keycloak: `default-roles-{realm}` (with `offline_access`,
  `uma_authorization`, `account/view-profile`, `account/manage-account`), the `account`,
  `admin-cli`, `broker`, `security-admin-console` and `realm-management` clients and their roles.
- JSON input is read as leniently as Keycloak's (Jackson): single values for lists, booleans
  and numbers for strings, trailing slashes in admin paths.
- Passwords are stored in Keycloak's credential format. New passwords use argon2id with
  Keycloak's parameters; `argon2`, `pbkdf2-sha512`, `pbkdf2-sha256` and `pbkdf2` hashes from a
  Keycloak export are verified as is, so users keep their passwords after migration.
- User ids from an export are preserved, so `sub` claims do not change.

## Not implemented yet

SAML identity brokering (gocloak as a SAML service provider), the SAML artifact binding and ECP,
Kerberos, script mappers, admin fine-grained permissions, reCAPTCHA, organizations,
FreeMarker themes (gocloak themes use Go templates; Keycloak message bundles work as is),
external token exchange (from identity providers), mutual TLS, JARM, implicit and hybrid flows.

The plan for these is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Compatibility

`scripts/compat/tokens.py` sets up the same realm on gocloak and on a real Keycloak through the
admin REST API, requests tokens for several scenarios (default scopes, optional scopes, no
`openid`, a client without full scope, client credentials, an invalid scope) and diffs the
claims of access tokens, ID tokens, refresh and offline tokens and userinfo, as well as the
responses for password policy violations, brute force lockouts, refresh token reuse, user
profile validation, and the built-in required actions and authentication flows:

```sh
scripts/compat/tokens.py --keycloak http://localhost:8180 --gocloak http://localhost:8080
```

The Keycloak side of that run is checked in under `internal/server/testdata/keycloak`
(recorded from Keycloak 26.0.7), and `TestKeycloakCompatibility` compares gocloak against it on
every test run.

The OpenID Foundation conformance suite runs in CI against gocloak with the Config OP, Basic OP
and Form Post OP certification plans (`scripts/conformance/run.sh`; it needs a build of the suite,
Java 21 and MongoDB), and `scripts/compat/saml_sp.py` uses a real Keycloak as SAML service provider.

## Layout

```
cmd/gocloak          CLI entry point
internal/model       domain types
internal/store       SQLite / PostgreSQL persistence, versioned migrations (migrations/)
internal/password    Keycloak-compatible password hashing
internal/policy      password policies
internal/otp         TOTP / HOTP
internal/userprofile declarative user profile and validators
internal/i18n        Keycloak message bundles (.properties) and formatting
internal/theme       themes (embedded default under theme/default/)
internal/account     account console and account REST API
internal/jwt         JWS (RS/PS/ES/HS), JWK, key generation
internal/service     realm provisioning, users, roles, keys, token verification
internal/oidc        protocol endpoints, authentication flow engine, required actions, login pages
internal/admin       admin REST API and realm import
internal/server      wiring, bootstrap, health, import on startup
internal/metrics     Prometheus metrics
internal/tracing     OpenTelemetry tracing (OTLP over HTTP)
charts/gocloak       Helm chart
scripts/loadtest     load generator and round-robin load balancer
```

## Development

```sh
go test ./...

# the same suite against PostgreSQL (each test gets its own schema)
GOCLOAK_TEST_POSTGRES_URL='postgres://user:pass@localhost:5432/gocloak?sslmode=disable' go test ./...
```

Schema changes go into a new numbered file in `internal/store/migrations/`;
migrations are applied automatically at startup and must work on both SQLite
and PostgreSQL. CI (`.github/workflows/ci.yml`) runs lint, both test suites
and a Docker smoke test.

The tests in `internal/server` run the real HTTP stack end to end: browser login with PKCE,
SSO, refresh, logout, client credentials, introspection and revocation, temporary passwords,
admin permissions and realm import.
