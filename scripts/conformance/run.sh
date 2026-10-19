#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite against gocloak: the
# "Config OP", "Basic OP" and "Form Post OP" certification plans, with a
# static client and discovery.
#
# Needs: a built conformance suite (SUITE_DIR with target/fapi-test-suite.jar),
# Java 21 (JAVA, default java), a MongoDB (MONGO_URI), a Python with httpx and
# pyparsing (PYTHON) and Go. Both servers are put behind TLS proxies, as the
# suite and the certification require https.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
SUITE_DIR=${SUITE_DIR:?SUITE_DIR is the conformance suite checkout}
MONGO_URI=${MONGO_URI:-mongodb://127.0.0.1:27017/test_suite}
JAVA=${JAVA:-java}
PYTHON=${PYTHON:-python3}
WORK=${WORK:-$(mktemp -d)}
SUITE_URL=https://localhost:18444
OP_URL=https://localhost:18445
PLANS=${PLANS:-"oidcc-config-certification-test-plan
oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"}

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

(cd "$ROOT" && go build -o "$WORK/gocloak" ./cmd/gocloak && go build -o "$WORK/tlsproxy" ./scripts/conformance/tlsproxy)
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin "$WORK/gocloak" start-dev --http-port 18083 \
  --db-url "$WORK/gocloak.db" --rate-limit 0 --proxy-headers xforwarded > "$WORK/gocloak.log" 2>&1 & pids+=($!)
"$WORK/tlsproxy" :18445 http://127.0.0.1:18083 > "$WORK/tlsproxy-op.log" 2>&1 & pids+=($!)
"$JAVA" -jar "$SUITE_DIR/target/fapi-test-suite.jar" --server.port=18443 --server.forward-headers-strategy=native \
  --fintechlabs.base_url=$SUITE_URL --fintechlabs.base_mtls_url=$SUITE_URL --fintechlabs.devmode=true \
  --spring.mongodb.uri="$MONGO_URI" --spring.data.mongodb.uri="$MONGO_URI" \
  "--openid.mongodb.targetFeatureCompatibilityVersion=" > "$WORK/suite.log" 2>&1 & pids+=($!)
"$WORK/tlsproxy" :18444 http://127.0.0.1:18443 > "$WORK/tlsproxy-suite.log" 2>&1 & pids+=($!)

for i in $(seq 1 120); do curl -sf localhost:18083/health/ready > /dev/null && break; sleep 1; done
for i in $(seq 1 120); do curl -skf "$SUITE_URL/api/plan?length=1" > /dev/null && break; sleep 2; done
python3 "$HERE/setup.py" http://localhost:18083 "$SUITE_URL"
python3 "$HERE/config.py" "$OP_URL" > "$WORK/config.json"

ids=()
while IFS= read -r plan; do
  [ -z "$plan" ] && continue
  (cd "$SUITE_DIR/scripts" && CONFORMANCE_SERVER=$SUITE_URL/ CONFORMANCE_SERVER_MTLS=$SUITE_URL/ CONFORMANCE_DEV_MODE=1 \
    "$PYTHON" run-test-plan.py "$plan" "$WORK/config.json" > "$WORK/run.log" 2>&1) || true
  ids+=($(grep -o "Created test plan, new id: [A-Za-z0-9]*" "$WORK/run.log" | awk '{print $NF}'))
done <<< "$PLANS"
"$PYTHON" "$HERE/results.py" "$SUITE_URL" "${ids[@]}"
