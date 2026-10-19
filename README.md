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

With Docker:

```sh
docker build -t gocloak .
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v gocloak-data:/data gocloak start-dev
```

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
| `--log-level` | `KC_LOG_LEVEL` | `info` (`debug` in dev mode) |
| — | `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD` (or legacy `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`) | admin created with the master realm on first start |

## What is implemented

**OpenID Connect / OAuth 2.0** (`/realms/{realm}/protocol/openid-connect/...`)

- Discovery (`/.well-known/openid-configuration`), JWKS (`/certs`), realm info (`/realms/{realm}`)
- Authorization code flow with login page, PKCE (`plain`, `S256`, and enforcement via the
  `pkce.code.challenge.method` client attribute), `response_mode` query / fragment / form_post,
  `prompt=none|login`, `max_age`, `login_hint`, `iss` in the response
- SSO across clients through a signed `KEYCLOAK_IDENTITY` cookie
- Grants: `authorization_code`, `password`, `client_credentials` (service accounts), `refresh_token`
- Client authentication: `client_secret_basic`, `client_secret_post`; public and bearer-only clients
- `userinfo`, token introspection, token revocation (RFC 7009)
- RP-initiated logout (`id_token_hint`, `post_logout_redirect_uri`, confirmation page) and
  Keycloak's back-channel logout with a refresh token
- CORS from the client's web origins (including `+`)
- Required action `UPDATE_PASSWORD` (temporary passwords)
- Client scopes and protocol mappers, as in Keycloak: the built-in scopes (`profile`, `email`,
  `roles`, `web-origins`, `acr`, `basic`, `address`, `phone`, `offline_access`, `microprofile-jwt`),
  default and optional scopes per realm and client, `invalid_scope` for unknown scopes, and
  mapper types for user properties and attributes, full name, address, realm / client roles,
  group membership, audience, audience resolve, hardcoded claim / role, role name, allowed
  origins, sub, acr and session notes
- Role scope mappings for clients without full scope allowed
- Tokens checked claim by claim against a real Keycloak 26 (see [Compatibility](#compatibility))

**Admin REST API** (`/admin/realms/...`, Keycloak paths and JSON)

- Realms: list, create (including full realm import with nested roles, clients, groups, users),
  get, partial update, delete, `logout-all`, `keys`, `partial-export`
- Users: search (`search`, `username`, `email`, `firstName`, `lastName`, `exact`, `enabled`,
  `q` attribute queries, `briefRepresentation`, `first`, `max`), count, CRUD with partial updates, `reset-password`, credentials, sessions,
  logout, group membership, role mappings (realm, client, composite, available)
- Clients: search, CRUD, client secret get / regenerate, service account user, user sessions,
  client roles, protocol mappers, default / optional client scopes, scope mappings,
  `evaluate-scopes` (example access token, ID token, userinfo, applied mappers)
- Client scopes: CRUD, protocol mappers, scope mappings, realm default / optional scopes
- Roles: realm and client roles CRUD, composites, users in role, `roles-by-id`
- Groups: tree listing, count, `group-by-path`, CRUD, children, members, role mappings
- Authorization exactly by Keycloak's roles: master `admin` (all realms), master `create-realm`,
  and `realm-management` client roles (`realm-admin`, `manage-users`, `view-users`,
  `manage-clients`, `view-clients`, `manage-realm`, `view-realm`, `query-*`, `create-client`).
  Admins cannot grant admin roles they do not hold themselves.

**Keycloak compatibility details**

- New realms get the same built-ins as Keycloak: `default-roles-{realm}` (with `offline_access`,
  `uma_authorization`, `account/view-profile`, `account/manage-account`), the `account`,
  `admin-cli` and `realm-management` clients and their roles.
- Passwords are stored in Keycloak's credential format. New passwords use argon2id with
  Keycloak's parameters; `argon2`, `pbkdf2-sha512`, `pbkdf2-sha256` and `pbkdf2` hashes from a
  Keycloak export are verified as is, so users keep their passwords after migration.
- User ids from an export are preserved, so `sub` claims do not change.

## Not implemented yet

SAML, identity brokering / social login, LDAP/Kerberos user federation, the declarative user
profile (gocloak keeps any user attribute, while Keycloak 26 drops undeclared ones by default),
script mappers, fine-grained authorization services (UMA), consent, offline tokens, OTP/WebAuthn,
registration and reset-password emails, brute force detection, events, themes, the admin and
account consoles, clustering, JWT client authentication, token exchange,
device flow, CIBA, PAR.

The plan for these is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Compatibility

`scripts/compat/tokens.py` sets up the same realm on gocloak and on a real Keycloak through the
admin REST API, requests tokens for several scenarios (default scopes, optional scopes, no
`openid`, a client without full scope, client credentials, an invalid scope) and diffs the
claims of access tokens, ID tokens and userinfo:

```sh
scripts/compat/tokens.py --keycloak http://localhost:8180 --gocloak http://localhost:8080
```

The Keycloak side of that run is checked in under `internal/server/testdata/keycloak`
(recorded from Keycloak 26.0.7), and `TestKeycloakCompatibility` compares gocloak against it on
every test run.

## Layout

```
cmd/gocloak          CLI entry point
internal/model       domain types
internal/store       SQLite / PostgreSQL persistence, versioned migrations (migrations/)
internal/password    Keycloak-compatible password hashing
internal/jwt         RS256 JWS and JWK
internal/service     realm provisioning, users, roles, keys, token verification
internal/oidc        protocol endpoints and login pages (templates/)
internal/admin       admin REST API and realm import
internal/server      wiring, bootstrap, health, import on startup
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
