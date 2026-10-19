# Performance

This page explains how gocloak's latency was measured and what was found.
The measurements come from a three-node cluster on one PostgreSQL database
behind a round-robin load balancer, without sticky sessions.

## Setup

Everything ran on a single small machine, so the numbers are a floor rather
than a target:

- **CPU / RAM:** Intel Pentium Silver J5005 (4 cores at 1.5 GHz, no AVX), 8 GB RAM.
- **Database:** PostgreSQL 16 on the same machine.
- **Nodes:** three gocloak nodes (`gocloak start --db postgres`,
  `--rate-limit 0`, `--log-level warn`) on ports 18301 to 18303.
- **Load balancer:** `go run ./scripts/loadtest -lb :18300 -backends ...`,
  which sends requests to each node in turn.
- **Load generator:** `go run ./scripts/loadtest`, also on the same machine.

The load generator and the load balancer share the machine's four cores
with the nodes and the database. Every request goes to the next node, so a
browser login runs its login page, form post and code exchange on three
different nodes.

The load tool's `-setup` flag creates realm `load` with a confidential
client and 50 users. The realm keeps the default keys (RS256, 2048 bits)
and the default password hashing (argon2id, as in Keycloak).

## Results

Each scenario ran for 60 s after a 5 s warm-up. The tool is closed-loop:
each worker sends its next request as soon as the previous one returns. No
request failed in any run.

**Moderate load** (2 workers):

| request | count | errors | req/s | p50 | p90 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| token (client_credentials) | 19009 | 0 | 317 | 6.1 ms | 7.2 ms | 8.8 ms | 12.4 ms |
| token (refresh_token) | 10715 | 0 | 179 | 10.9 ms | 12.4 ms | 13.8 ms | 17.4 ms |
| login page | 1682 | 0 | 28 | 2.2 ms | 2.8 ms | 4.5 ms | 7.6 ms |
| login form post | 1682 | 0 | 28 | 57.2 ms | 61.0 ms | 65.3 ms | 69.9 ms |
| token (authorization_code) | 1682 | 0 | 28 | 11.1 ms | 11.9 ms | 13.7 ms | 18.3 ms |

**Saturated** (16 workers). Throughput is no higher than with 4 workers, so
the extra latency is time spent queueing for CPU:

| request | count | errors | req/s | p50 | p90 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| token (client_credentials) | 30523 | 0 | 509 | 29.9 ms | 46.9 ms | 66.3 ms | 206.4 ms |
| token (refresh_token) | 17282 | 0 | 288 | 53.8 ms | 78.3 ms | 103.8 ms | 208.2 ms |
| login page | 2530 | 0 | 42 | 17.3 ms | 58.1 ms | 101.5 ms | 201.5 ms |
| login form post | 2530 | 0 | 42 | 273.6 ms | 392.7 ms | 491.9 ms | 612.8 ms |
| token (authorization_code) | 2530 | 0 | 42 | 61.1 ms | 140.7 ms | 217.5 ms | 295.2 ms |

**p99 latency of the token endpoint:**

- Under moderate load: 8.8 ms for client credentials, 13.8 ms for a refresh
  and 13.7 ms for a code exchange.
- Saturated: 66 ms, 104 ms and 218 ms.

## Where the time goes

While the client credentials scenario ran, the three nodes used about three
cores and PostgreSQL used little more than a tenth of one.

**Token requests** are bound by signing. One RS256 signature with a
2048-bit key takes 4.9 ms on this CPU (Go's constant-time RSA). It accounts
for about three quarters of a token request's CPU time. A refresh with scope
`openid` signs two RSA tokens, the access token and the ID token, so it
costs about twice as much as a client credentials grant. The refresh token
itself is HS512 and cheap.

**The login form post** is bound by password hashing. Argon2id with
Keycloak's parameters (5 iterations, 7 MiB) makes up most of its 57 ms
median.

**The database** sees about 6 queries per token request: the user, their
role and group mappings, and the session. The realm, the client, the client
scopes, the protocol mappers and the roles come from the configuration cache
(`internal/store/cache.go`). Writes to them empty the cache on every node
(PostgreSQL LISTEN/NOTIFY), and cached entries also expire after a minute.

## Reproducing

```sh
# three nodes on a PostgreSQL database
for i in 1 2 3; do
  KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  gocloak start --http-port 1830$i --http-management-port 1940$i \
    --hostname http://localhost:18300 --rate-limit 0 --log-level warn \
    --db postgres --db-url postgres://user:pass@localhost/gocloak &
done
go run ./scripts/loadtest -lb :18300 \
  -backends http://localhost:18301,http://localhost:18302,http://localhost:18303 &

go run ./scripts/loadtest -url http://localhost:18300 -setup -users 50 -c 2 -d 60s
go run ./scripts/loadtest -url http://localhost:18300 -users 50 -c 16 -d 60s
```

Turn the rate limit off (`--rate-limit 0`) or set `--proxy-headers xforwarded`
on the nodes. Without that, all load comes from one client address and hits
the per-IP limit.

For profiling a single node without the network, there are Go benchmarks:

```sh
go test -run XXX -bench . -benchtime 5s ./internal/server
```
