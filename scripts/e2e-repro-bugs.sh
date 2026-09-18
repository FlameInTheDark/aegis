#!/usr/bin/env bash
# e2e repro of the user-reported demo-deployment bugs, against a REAL
# PostgreSQL 16 (fresh database) + real nats-server + redis stub:
#
#   1. POST /scans  discovery_safe profile   -> was 400 scans_profile_fkey
#   2. GET  /topology?site_id=               -> was 500 (empty uuid)
#   3. POST /sites/:id/networks no gateway   -> was 400 invalid inet ""
#   4. GET  /audit-log?limit=100             -> was 500 (NULL scans)
#   5. GET  /feeds                           -> was 500 (NULL scans)
# plus regression on scans/findings/matches lists (same bug classes).
set -uo pipefail

ROOT=/home/z/my-project
INFRA=$ROOT/scripts/sandbox-infra
PGT=/tmp/my-project/scripts/pgtest
RUN=/tmp/aegis-repro
mkdir -p $RUN
export PATH=$PATH:$PGT/bin:/home/z/go/bin

cleanup() {
  [ -n "${SRV_PID:-}" ] && kill $SRV_PID 2>/dev/null
  [ -n "${NATS_PID:-}" ] && kill $NATS_PID 2>/dev/null
  [ -n "${RDS_PID:-}" ] && kill $RDS_PID 2>/dev/null
  $PGT/bin/pg_ctl -D $PGT/data-e2e -m fast stop >/dev/null 2>&1
}
trap cleanup EXIT

jsonget() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }
PASS=0; FAIL=0
check() { # name expected actual body
  if [ "$2" = "$3" ]; then echo "  PASS: $1 (HTTP $3)"; PASS=$((PASS+1));
  else echo "  FAIL: $1 expected $2 got $3  $(echo "$4" | head -c 220)"; FAIL=$((FAIL+1)); fi
}

echo "== 1. infrastructure =="
$PGT/bin/pg_ctl -D $PGT/data-e2e -o "-p 5432 -k $PGT/sock -c listen_addresses=127.0.0.1" -l $RUN/pg.log restart >/dev/null 2>&1 || \
$PGT/bin/pg_ctl -D $PGT/data-e2e -o "-p 5432 -k $PGT/sock -c listen_addresses=127.0.0.1" -l $RUN/pg.log start >/dev/null 2>&1
for i in $(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/5432) 2>/dev/null && break; sleep 0.5; done
echo "  postgres up (fresh cluster)"

$INFRA/bin/nats-server -js -a 127.0.0.1 -p 4222 -store_dir $RUN/nats > $RUN/nats.log 2>&1 &
NATS_PID=$!
$INFRA/bin/redis-stub > $RUN/redis.log 2>&1 &
RDS_PID=$!
sleep 1
echo "  nats + redis-stub up"

echo "== 2. migrations + demo seed (fresh DB, before server boot) =="
URL="postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable"
go -C $ROOT run ./scripts/seedtool "$URL" $ROOT/scripts/sandbox-infra/reset.sql >/dev/null 2>&1
AEGIS_DATABASE_URL="$URL" go -C $ROOT run ./scripts/migrate > $RUN/migrate.log 2>&1 || { echo "MIGRATE FAILED"; cat $RUN/migrate.log; exit 1; }
go -C $ROOT run ./scripts/seedtool "$URL" $ROOT/scripts/seed/demo.sql > $RUN/seed.log 2>&1 \
  || { echo "SEED FAILED"; tail -5 $RUN/seed.log; exit 1; }
echo "  migrations + seed applied"

echo "== 3. build + boot server + scanner =="
go -C $ROOT build -ldflags "-s -w -X main.version=$(cat $ROOT/VERSION 2>/dev/null || echo dev)" -o $RUN/aegis-server ./cmd/server || exit 1
go -C $ROOT build -o $RUN/aegis-scanner ./cmd/scanner || exit 1
AEGIS_ENV=development \
AEGIS_LOG_LEVEL=info \
AEGIS_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable \
AEGIS_REDIS_URL=redis://127.0.0.1:6379/0 \
AEGIS_NATS_URL=nats://127.0.0.1:4222 \
AEGIS_JWT_SECRET=e2e-secret-key-0123456789abcdef0123456789abcdef \
AEGIS_BOOTSTRAP_ADMIN_EMAIL=admin@aegis.local \
AEGIS_BOOTSTRAP_ADMIN_PASSWORD=aegis-demo-admin-2026 \
AEGIS_DEMO_MODE=true \
$RUN/aegis-server > $RUN/server.log 2>&1 &
SRV_PID=$!
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz 2>/dev/null)
  [ "$code" != "000" ] && break
  sleep 1
done
[ "$code" = "200" ] || { echo "SERVER NEVER HEALTHY"; tail -40 $RUN/server.log; exit 1; }
grep -c "scan profiles synced" $RUN/server.log >/dev/null && echo "  profiles synced at boot"
grep -E "bootstrap skipped" $RUN/server.log | head -1

ORG="00000000-0000-4000-8000-000000000001"
SITE_HQ="00000000-0000-4000-8000-000000000010"
SITE_DC="00000000-0000-4000-8000-000000000011"

# The scan-creation API refuses scans for sites without a healthy scanner
# (409). Boot a simulated-engine scanner for the HQ site before creating scans.
AEGIS_ENV=development AEGIS_LOG_LEVEL=info \
AEGIS_DATABASE_URL="$URL" \
AEGIS_REDIS_URL=redis://127.0.0.1:6379/0 \
AEGIS_NATS_URL=nats://127.0.0.1:4222 \
AEGIS_SCANNER_SITE_ID=$SITE_HQ \
AEGIS_SCANNER_NAME=repro-scanner \
$RUN/aegis-scanner > $RUN/scanner.log 2>&1 &
SCN_PID=$!
echo "  scanner booting for site $SITE_HQ"

echo "== 4. auth =="
code=$(curl -s -o $RUN/login.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@aegis.local","password":"aegis-demo-admin-2026"}')
[ "$code" = "200" ] || { echo "LOGIN FAILED"; cat $RUN/login.json; tail -20 $RUN/server.log; exit 1; }
ACCESS=$(jsonget "['access_token']" < $RUN/login.json)
AUTH="Authorization: Bearer $ACCESS"
echo "  login OK"

# Wait until the scanner is registered and healthy for the HQ site.
for i in $(seq 1 20); do
  cnt=$(curl -s "http://127.0.0.1:8080/api/v1/scanners" -H "$AUTH" | python3 -c "import json,sys;items=json.load(sys.stdin).get('items') or [];print(sum(1 for s in items if s.get('site_id')=='$SITE_HQ' and s.get('health')=='healthy'))" 2>/dev/null || echo 0)
  [ "${cnt:-0}" -ge 1 ] && break
  sleep 1
done
echo "  scanner registered (healthy=${cnt:-0})"

echo "== 5. USER BUG 1: POST /scans (discovery_safe) =="
code=$(curl -s -o $RUN/scan.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"discovery_safe scan\",\"profile\":\"discovery_safe\",\"targets\":[\"192.168.1.0/24\"],\"denylist\":[],\"engine\":\"nmap\",\"confirm_elevated\":false}")
check "POST /scans" 201 "$code" "$(cat $RUN/scan.json)"
SCAN_ID=$(jsonget "['scan']['id']" < $RUN/scan.json 2>/dev/null)

echo "== 6. USER BUG 2: GET /topology?site_id= =="
code=$(curl -s -o $RUN/topo.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/topology?site_id=" -H "$AUTH")
check "GET /topology?site_id= (empty)" 200 "$code" "$(cat $RUN/topo.json)"
code=$(curl -s -o $RUN/topo2.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/topology?site_id=not-a-uuid" -H "$AUTH")
check "GET /topology?site_id=malformed -> 400" 400 "$code" "$(cat $RUN/topo2.json)"
code=$(curl -s -o $RUN/topo3.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/topology?site_id=$SITE_HQ" -H "$AUTH")
check "GET /topology?site_id=<uuid>" 200 "$code" "$(cat $RUN/topo3.json)"

echo "== 7. USER BUG 3: POST /sites/:id/networks (no gateway) =="
code=$(curl -s -o $RUN/net.json -w '%{http_code}' -X POST "http://127.0.0.1:8080/api/v1/sites/$SITE_DC/networks" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"cidr":"192.168.1.0/24","name":"192.168.1.0/24"}')
check "POST /sites/:id/networks" 201 "$code" "$(cat $RUN/net.json)"
NET_ID=$(jsonget "['id']" < $RUN/net.json 2>/dev/null)
code=$(curl -s -o $RUN/nets.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/sites/$SITE_DC/networks" -H "$AUTH")
check "GET /sites/:id/networks (list incl. NULL gateway)" 200 "$code" "$(cat $RUN/nets.json)"
code=$(curl -s -o $RUN/netbad.json -w '%{http_code}' -X POST "http://127.0.0.1:8080/api/v1/sites/$SITE_DC/networks" \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"cidr":"nonsense","name":"x"}')
check "POST /sites/:id/networks bad CIDR -> 400" 400 "$code" "$(cat $RUN/netbad.json)"

echo "== 8. USER BUG 4: GET /audit-log =="
code=$(curl -s -o $RUN/audit.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/audit-log?limit=100" -H "$AUTH")
check "GET /audit-log?limit=100" 200 "$code" "$(cat $RUN/audit.json)"
TOTAL=$(jsonget "['total']" < $RUN/audit.json 2>/dev/null)
echo "  audit rows: $TOTAL (seed rows have NULL actor_name/ip and are included)"

echo "== 9. USER BUG 5: GET /feeds =="
code=$(curl -s -o $RUN/feeds.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/feeds" -H "$AUTH")
check "GET /feeds" 200 "$code" "$(cat $RUN/feeds.json)"

echo "== 10. regression: same bug class on other list endpoints =="
code=$(curl -s -o $RUN/scans.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/scans?limit=50" -H "$AUTH")
check "GET /scans (scanner_id/error/schedule_cron NULL)" 200 "$code" "$(cat $RUN/scans.json)"
code=$(curl -s -o $RUN/f.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/findings?limit=50" -H "$AUTH")
check "GET /findings (osv_id/software_id NULL)" 200 "$code" "$(cat $RUN/f.json)"
code=$(curl -s -o $RUN/dm.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/detections/matches?limit=50" -H "$AUTH")
check "GET /detections/matches (asset_id NULL)" 200 "$code" "$(cat $RUN/dm.json)"
code=$(curl -s -o $RUN/sc.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/scanners" -H "$AUTH")
check "GET /scanners" 200 "$code" "$(cat $RUN/sc.json)"
code=$(curl -s -o $RUN/sch.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/schedules" -H "$AUTH")
check "GET /schedules" 200 "$code" "$(cat $RUN/sch.json)"
code=$(curl -s -o $RUN/r.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/reports" -H "$AUTH")
check "GET /reports" 200 "$code" "$(cat $RUN/r.json)"
code=$(curl -s -o $RUN/a.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/agents" -H "$AUTH")
check "GET /agents" 200 "$code" "$(cat $RUN/a.json)"
code=$(curl -s -o $RUN/as.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/assets?limit=50" -H "$AUTH")
check "GET /assets" 200 "$code" "$(cat $RUN/as.json)"
code=$(curl -s -o $RUN/sv.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/services?limit=50" -H "$AUTH")
check "GET /services" 200 "$code" "$(cat $RUN/sv.json)"
code=$(curl -s -o $RUN/v.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?limit=50" -H "$AUTH")
check "GET /vulnerabilities" 200 "$code" "$(cat $RUN/v.json)"
code=$(curl -s -o $RUN/ev.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/events?limit=10" -H "$AUTH")
check "GET /events (no CH -> 503)" 503 "$code" "$(cat $RUN/ev.json)" || true
if [ -n "${SCAN_ID:-}" ]; then
  code=$(curl -s -o $RUN/st.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/scans/$SCAN_ID/tasks" -H "$AUTH")
  check "GET /scans/:id/tasks" 200 "$code" "$(cat $RUN/st.json)"
fi

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
