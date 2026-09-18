#!/usr/bin/env bash
# e2e feature verification against real PostgreSQL 16 + nats-server:
#   A. full-host scan: high ports (3389/5432/8080/9200), service+OS fingerprint
#   B. topology: traceroute-driven nodes/edges appear after a scan
#   C. CVE correlation: scan completion -> findings for detected services
#   D. full_audit profile accepted; on-demand correlate endpoint
#   E. device-type classification (workstation/phone/camera/printer)
#   F. address-aware identity: rescans update assets, never copy them
#   G. trace + fingerprint profiles
#   H. CVE search: substring on id/description/reference + score filter
set -uo pipefail

ROOT=/home/z/my-project
INFRA=$ROOT/scripts/sandbox-infra
PGT=/tmp/my-project/scripts/pgtest
RUN=/tmp/aegis-features
mkdir -p $RUN
export PATH=$PATH:$PGT/bin:/home/z/go/bin

cleanup() {
  [ -n "${SCN_PID:-}" ] && kill $SCN_PID 2>/dev/null
  [ -n "${SRV_PID:-}" ] && kill $SRV_PID 2>/dev/null
  [ -n "${NATS_PID:-}" ] && kill $NATS_PID 2>/dev/null
  [ -n "${RDS_PID:-}" ] && kill $RDS_PID 2>/dev/null
  $PGT/bin/pg_ctl -D $PGT/data-e2e -m fast stop >/dev/null 2>&1
}
trap cleanup EXIT

jsonget() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }
PASS=0; FAIL=0
check() { # name expected actual body
  if [ "$2" = "$3" ]; then echo "  PASS: $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL: $1 expected $2 got $3  $(echo "$4" | head -c 200)"; FAIL=$((FAIL+1)); fi
}

# wait_scan SCAN_ID: poll until the scan completes (or fails); echoes 1/0.
wait_scan() {
  local sid=$1 st
  for i in $(seq 1 80); do
    st=$(curl -s "http://127.0.0.1:8080/api/v1/scans/$sid" -H "$AUTH" | jsonget "['scan']['state']" 2>/dev/null)
    [ "$st" = "completed" ] && { echo 1; return; }
    [ "$st" = "failed" ] && { echo 0; return; }
    sleep 1
  done
  echo 0
}

echo "== 1. infrastructure =="
$PGT/bin/pg_ctl -D $PGT/data-e2e -o "-p 5432 -k $PGT/sock -c listen_addresses=127.0.0.1" -l $RUN/pg.log restart >/dev/null 2>&1 || \
$PGT/bin/pg_ctl -D $PGT/data-e2e -o "-p 5432 -k $PGT/sock -c listen_addresses=127.0.0.1" -l $RUN/pg.log start >/dev/null 2>&1
for i in $(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/5432) 2>/dev/null && break; sleep 0.5; done
echo "  postgres up"
$INFRA/bin/nats-server -js -a 127.0.0.1 -p 4222 -store_dir $RUN/nats > $RUN/nats.log 2>&1 &
NATS_PID=$!
$INFRA/bin/redis-stub > $RUN/redis.log 2>&1 &
RDS_PID=$!
sleep 1

echo "== 2. migrations + demo seed (fresh DB) =="
URL="postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable"
go -C $ROOT run ./scripts/seedtool "$URL" $ROOT/scripts/sandbox-infra/reset.sql >/dev/null 2>&1
AEGIS_DATABASE_URL="$URL" go -C $ROOT run ./scripts/migrate > $RUN/migrate.log 2>&1 || { echo "MIGRATE FAILED"; cat $RUN/migrate.log; exit 1; }
go -C $ROOT run ./scripts/seedtool "$URL" $ROOT/scripts/seed/demo.sql > $RUN/seed.log 2>&1 || { echo "SEED FAILED"; tail -5 $RUN/seed.log; exit 1; }
echo "  migrations + seed applied"

echo "== 3. build + boot server =="
go -C $ROOT build -ldflags "-s -w -X main.version=$(cat $ROOT/VERSION 2>/dev/null || echo dev)" -o $RUN/aegis-server ./cmd/server || exit 1
go -C $ROOT build -o $RUN/aegis-scanner ./cmd/scanner || exit 1
AEGIS_ENV=development AEGIS_LOG_LEVEL=info \
AEGIS_DATABASE_URL="$URL" \
AEGIS_REDIS_URL=redis://127.0.0.1:6379/0 \
AEGIS_NATS_URL=nats://127.0.0.1:4222 \
AEGIS_JWT_SECRET=e2e-secret-key-0123456789abcdef0123456789abcdef \
AEGIS_BOOTSTRAP_ADMIN_EMAIL=admin@aegis.local \
AEGIS_BOOTSTRAP_ADMIN_PASSWORD=aegis-demo-admin-2026 \
AEGIS_DEMO_MODE=true \
$RUN/aegis-server > $RUN/server.log 2>&1 &
SRV_PID=$!
for i in $(seq 1 80); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 1
done
check "server healthy" 200 "$code" ""

echo "== 4. auth (cookie-based rotating refresh) =="
code=$(curl -s -o $RUN/login.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -c $RUN/cookies.jar \
  -d '{"email":"admin@aegis.local","password":"aegis-demo-admin-2026"}')
check "login" 200 "$code" "$(cat $RUN/login.json)"
ACCESS=$(jsonget "['access_token']" < $RUN/login.json)
AUTH="Authorization: Bearer $ACCESS"

ORG="00000000-0000-4000-8000-000000000001"
SITE_HQ="00000000-0000-4000-8000-000000000010"

echo "== 5. boot scanner (simulated engine, site HQ) =="
AEGIS_ENV=development AEGIS_LOG_LEVEL=info \
AEGIS_DATABASE_URL="$URL" \
AEGIS_REDIS_URL=redis://127.0.0.1:6379/0 \
AEGIS_NATS_URL=nats://127.0.0.1:4222 \
AEGIS_SCANNER_SITE_ID=$SITE_HQ \
AEGIS_SCANNER_NAME=e2e-scanner \
$RUN/aegis-scanner > $RUN/scanner.log 2>&1 &
SCN_PID=$!
# Give the scanner time to register (needed by the scan-creation guard).
for i in $(seq 1 15); do
  cnt=$(curl -s "http://127.0.0.1:8080/api/v1/scanners" -H "$AUTH" | python3 -c "import json,sys;items=json.load(sys.stdin).get('items') or [];print(sum(1 for s in items if s.get('site_id')=='$SITE_HQ' and s.get('health')=='healthy'))" 2>/dev/null || echo 0)
  [ "${cnt:-0}" -ge 1 ] && break
  sleep 1
done
echo "  scanner registered (healthy=$cnt)"

echo "== 6. create inventory scan on HQ =="
code=$(curl -s -o $RUN/scan.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"e2e inventory\",\"profile\":\"inventory\",\"targets\":[\"192.168.10.0/24\"],\"denylist\":[],\"engine\":\"simulated\",\"confirm_elevated\":false}")
check "POST /scans (inventory)" 201 "$code" "$(cat $RUN/scan.json)"
SCAN_ID=$(jsonget "['scan']['id']" < $RUN/scan.json 2>/dev/null)

echo "== 7. wait for scan completion + correlation =="
DONE=""
for i in $(seq 1 80); do
  st=$(curl -s "http://127.0.0.1:8080/api/v1/scans/$SCAN_ID" -H "$AUTH" | jsonget "['scan']['state']" 2>/dev/null)
  [ "$st" = "completed" ] && { DONE=1; break; }
  [ "$st" = "failed" ] && { echo "  scan failed:"; curl -s "http://127.0.0.1:8080/api/v1/scans/$SCAN_ID" -H "$AUTH" | head -c 400; echo; break; }
  sleep 1
done
check "scan completed" 1 "${DONE:-0}" ""
code=$(curl -s -o $RUN/topo.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/topology?site_id=$SITE_HQ" -H "$AUTH")
check "GET /topology (site)" 200 "$code" ""
NODES=$(jsonget "['nodes']" < $RUN/topo.json 2>/dev/null | python3 -c "import sys;print(len(sys.stdin.read().split('},{'))) " 2>/dev/null)
NODES=$(python3 -c "import json;d=json.load(open('$RUN/topo.json'));print(len(d.get('nodes') or []))")
EDGES=$(python3 -c "import json;d=json.load(open('$RUN/topo.json'));print(len(d.get('edges') or []))")
echo "  topology nodes=$NODES edges=$EDGES"
[ "${NODES:-0}" -ge 2 ] && check "topology has gateway+host nodes" 1 1 "" || check "topology has gateway+host nodes" 1 0 "nodes=$NODES"
[ "${EDGES:-0}" -ge 1 ] && check "topology has edges" 1 1 "" || check "topology has edges" 1 0 "edges=$EDGES"

echo "== 8. full-host scan results: high ports + fingerprints + OS =="
code=$(curl -s -o $RUN/svcs.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/services?limit=200" -H "$AUTH")
check "GET /services" 200 "$code" ""
HIGH=$(python3 -c "
import json;d=json.load(open('$RUN/svcs.json'))
ports=sorted({(s.get('port')) for s in (d.get('items') or [])})
print(','.join(str(p) for p in ports if p in (3389,5432,8080,9200)))")
echo "  high ports seen: $HIGH"
[ "${HIGH:-}" = "3389,5432,8080,9200" ] && check "high ports discovered (top-N fix)" 1 1 "" || check "high ports discovered (top-N fix)" 1 0 "high=$HIGH"
PROD=$(python3 -c "
import json;d=json.load(open('$RUN/svcs.json'))
prods=sorted({(s.get('product') or '') for s in (d.get('items') or []) if s.get('product')})
print('YES' if 'OpenSSH' in prods and 'PostgreSQL' in prods else 'NO')")
check "service versions fingerprinted (OpenSSH, PostgreSQL)" "YES" "$PROD" "$PROD"
code=$(curl -s -o $RUN/assets.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/assets?limit=200" -H "$AUTH")
OSSEEN=$(python3 -c "
import json;d=json.load(open('$RUN/assets.json'))
os=[(a.get('os_family') or '') for a in (d.get('items') or [])]
print('YES' if any(o for o in os) else 'NO')" 2>/dev/null)
check "OS recorded on assets" "YES" "$OSSEEN" ""

echo "== 8b. device-type classification (phone/camera/printer/computer) =="
DTYPES=$(python3 -c "
import json;d=json.load(open('$RUN/assets.json'))
types={(a.get('device_type') or '') for a in (d.get('items') or [])}
need={'workstation','mobile','camera','printer'}
print('YES' if need <= types else 'MISSING:' + ','.join(sorted(need - types)))" 2>/dev/null)
check "device classes classified" "YES" "$DTYPES" "$DTYPES"
OSMIX=$(python3 -c "
import json;d=json.load(open('$RUN/assets.json'))
oses={(a.get('os_name') or '') for a in (d.get('items') or [])}
print('YES' if 'Android' in oses else 'NO')" 2>/dev/null)
check "per-device OS fingerprints (Android seen)" "YES" "$OSMIX" ""

echo "== 9. CVE correlation produced findings =="
FOUND=$(python3 -c "
import json
try:
    d=json.load(open('$RUN/f.json'))
except Exception:
    d={}
" 2>/dev/null; true)
code=$(curl -s -o $RUN/findings.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/findings?limit=200" -H "$AUTH")
check "GET /findings" 200 "$code" ""
TERRAPIN=$(python3 -c "
import json;d=json.load(open('$RUN/findings.json'))
cves=[(f.get('cve_id') or f.get('cveId') or '') for f in (d.get('items') or [])]
print('YES' if 'CVE-2023-48795' in cves else 'NO')")
check "finding for CVE-2023-48795 (OpenSSH 9.6 vs demo CPE)" "YES" "$TERRAPIN" "$(cat $RUN/findings.json | head -c 300)"

echo "== 10. on-demand correlation endpoint =="
code=$(curl -s -o $RUN/corr.json -w '%{http_code}' -X POST "http://127.0.0.1:8080/api/v1/vulnerabilities/correlate" -H "$AUTH")
check "POST /vulnerabilities/correlate" 202 "$code" "$(cat $RUN/corr.json)"

echo "== 11. full_audit profile =="
code=$(curl -s -o $RUN/fa.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"e2e full audit\",\"profile\":\"full_audit\",\"targets\":[\"192.168.10.0/24\"],\"denylist\":[],\"engine\":\"simulated\",\"confirm_elevated\":false}")
check "POST /scans (full_audit)" 201 "$code" "$(cat $RUN/fa.json)"

echo "== 12. address-aware identity: rescan makes no asset copies =="
BEFORE=$(python3 -c "import json;d=json.load(open('$RUN/assets.json'));print(len(d.get('items') or []))")
code=$(curl -s -o $RUN/scan2.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"e2e rescan\",\"profile\":\"inventory\",\"targets\":[\"192.168.10.0/24\"],\"denylist\":[],\"engine\":\"simulated\",\"confirm_elevated\":false}")
check "POST /scans (rescan)" 201 "$code" "$(cat $RUN/scan2.json)"
SCAN2=$(jsonget "['scan']['id']" < $RUN/scan2.json 2>/dev/null)
DONE2=$(wait_scan "$SCAN2")
check "rescan completed" 1 "${DONE2:-0}" ""
code=$(curl -s -o $RUN/assets2.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/assets?limit=200" -H "$AUTH")
check "GET /assets (after rescan)" 200 "$code" ""
AFTER=$(python3 -c "import json;d=json.load(open('$RUN/assets2.json'));print(len(d.get('items') or []))")
echo "  assets before=$BEFORE after=$AFTER"
[ "${BEFORE:-0}" -gt 0 ] && [ "${AFTER:-0}" -le "${BEFORE:-0}" ] && check "rescan created no asset copies" 1 1 "" || check "rescan created no asset copies" 1 0 "before=$BEFORE after=$AFTER"
DUP=$(python3 -c "
import json;d=json.load(open('$RUN/assets2.json'))
hosts=[a.get('hostname') or '' for a in (d.get('items') or [])]
import collections
c=collections.Counter(hosts)
print(','.join(sorted(h for h,n in c.items() if n>1 and h)) or 'NONE')")
check "no duplicate hostnames in inventory" "NONE" "$DUP" "$DUP"

echo "== 13. trace profile (fast: ping + traceroute, no ports) =="
code=$(curl -s -o $RUN/trace.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"e2e trace\",\"profile\":\"trace\",\"targets\":[\"192.168.10.0/24\"],\"denylist\":[],\"engine\":\"simulated\",\"confirm_elevated\":false}")
check "POST /scans (trace)" 201 "$code" "$(cat $RUN/trace.json)"
TRACE_ID=$(jsonget "['scan']['id']" < $RUN/trace.json 2>/dev/null)
TRDONE=$(wait_scan "$TRACE_ID")
check "trace scan completed" 1 "${TRDONE:-0}" ""
code=$(curl -s -o $RUN/topo2.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/topology?site_id=$SITE_HQ" -H "$AUTH")
EDGES2=$(python3 -c "import json;d=json.load(open('$RUN/topo2.json'));print(len(d.get('edges') or []))")
echo "  topology edges after trace=$EDGES2"
[ "${EDGES2:-0}" -ge 1 ] && check "trace built connection lines" 1 1 "" || check "trace built connection lines" 1 0 "edges=$EDGES2"

echo "== 14. fingerprint profile (device/OS pass, latest wins) =="
code=$(curl -s -o $RUN/fp.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"e2e fingerprint\",\"profile\":\"fingerprint\",\"targets\":[\"192.168.10.0/24\"],\"denylist\":[],\"engine\":\"simulated\",\"confirm_elevated\":false}")
check "POST /scans (fingerprint)" 201 "$code" "$(cat $RUN/fp.json)"
FP_ID=$(jsonget "['scan']['id']" < $RUN/fp.json 2>/dev/null)
FPDONE=$(wait_scan "$FP_ID")
check "fingerprint scan completed" 1 "${FPDONE:-0}" ""
code=$(curl -s -o $RUN/assets3.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/assets?limit=200" -H "$AUTH")
REFRESH=$(python3 -c "
import json;d=json.load(open('$RUN/assets3.json'))
oses={(a.get('os_name') or '') for a in (d.get('items') or [])}
dts={(a.get('device_type') or '') for a in (d.get('items') or [])}
print('YES' if 'Android' in oses and 'mobile' in dts else 'NO')" 2>/dev/null)
check "fingerprint refreshed asset device/OS data" "YES" "$REFRESH" ""

echo "== 15. CVE search: substring + content + filters =="
code=$(curl -s -o $RUN/vs1.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?search=2023-48" -H "$AUTH")
check "GET /vulnerabilities?search=2023-48" 200 "$code" ""
SUB=$(python3 -c "
import json;d=json.load(open('$RUN/vs1.json'))
ids=[(v.get('cve_id') or '') for v in (d.get('items') or [])]
print('YES' if 'CVE-2023-48795' in ids else 'NO')" 2>/dev/null)
check "substring search finds CVE-2023-48795" "YES" "$SUB" "$(cat $RUN/vs1.json | head -c 200)"
code=$(curl -s -o $RUN/vs2.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?search=Log4j" -H "$AUTH")
DESC=$(python3 -c "
import json;d=json.load(open('$RUN/vs2.json'))
ids=[(v.get('cve_id') or '') for v in (d.get('items') or [])]
print('YES' if 'CVE-2021-44228' in ids else 'NO')" 2>/dev/null)
check "description search finds Log4Shell" "YES" "$DESC" "$(cat $RUN/vs2.json | head -c 200)"
code=$(curl -s -o $RUN/vs3.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?search=terrapin-attack.com" -H "$AUTH")
REF=$(python3 -c "
import json;d=json.load(open('$RUN/vs3.json'))
ids=[(v.get('cve_id') or '') for v in (d.get('items') or [])]
print('YES' if 'CVE-2023-48795' in ids else 'NO')" 2>/dev/null)
check "reference-URL search finds CVE-2023-48795" "YES" "$REF" "$(cat $RUN/vs3.json | head -c 200)"
code=$(curl -s -o $RUN/vs4.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?min_score=9" -H "$AUTH")
HISCORE=$(python3 -c "
import json;d=json.load(open('$RUN/vs4.json'))
items=(d.get('items') or [])
ids=[(v.get('cve_id') or '') for v in items]
print('YES' if 'CVE-2021-44228' in ids and 'CVE-2024-21762' in ids else 'NO')" 2>/dev/null)
check "CVSS >= 9 filter returns Log4j + FortiOS" "YES" "$HISCORE" "$(cat $RUN/vs4.json | head -c 200)"

echo "== 16. bare-IP scan scope + asset bundle arrays (null-crash regression) =="
# Regression: POST /scans with a plain IP ("192.168.1.1") failed with
# `invalid CIDR "192.168.1.1"; scope is empty`.
code=$(curl -s -o $RUN/bare.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"site_id\":\"$SITE_HQ\",\"name\":\"e2e bare-ip trace\",\"profile\":\"trace\",\"targets\":[\"192.168.1.1\"],\"denylist\":[],\"engine\":\"simulated\",\"confirm_elevated\":false}")
check "POST /scans accepts bare IP target" 201 "$code" "$(cat $RUN/bare.json)"
BARE_ID=$(jsonget "['scan']['id']" < $RUN/bare.json 2>/dev/null)
BAREDONE=$(wait_scan "$BARE_ID")
check "bare-IP trace scan completed" 1 "${BAREDONE:-0}" ""
# The trace-only asset must expose services as [] (never null) — the asset
# detail UI crashed with `Cannot read properties of null (reading 'length')`.
AID=$(curl -s "http://127.0.0.1:8080/api/v1/assets?site_id=$SITE_HQ&search=192.168.1.11" -H "$AUTH" | jsonget "['items'][0]['id']" 2>/dev/null)
code=$(curl -s -o $RUN/bundle1.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/assets/$AID" -H "$AUTH")
check "GET /assets/{trace-only asset}" 200 "$code" ""
NULLCHK=$(python3 -c "
import json;d=json.load(open('$RUN/bundle1.json'))
ok=all(isinstance(d.get(k), list) for k in ('interfaces','services','software'))
print('YES' if ok else 'NULL')" 2>/dev/null)
check "asset bundle lists are arrays (services=[]) for trace-only asset" "YES" "$NULLCHK" "$(cat $RUN/bundle1.json | head -c 200)"
# An inventory-scanned asset must actually expose its detected ports.
IID=$(curl -s "http://127.0.0.1:8080/api/v1/assets?site_id=$SITE_HQ&search=192.168.10.11" -H "$AUTH" | jsonget "['items'][0]['id']" 2>/dev/null)
curl -s -o $RUN/bundle2.json "http://127.0.0.1:8080/api/v1/assets/$IID" -H "$AUTH"
PORTCHK=$(python3 -c "
import json;d=json.load(open('$RUN/bundle2.json'))
svcs=d.get('services') or []
ports={(s.get('port')) for s in svcs}
print('YES' if {22,443,3389,5432,8080,9200} <= ports else 'MISSING')" 2>/dev/null)
check "asset bundle shows detected ports/services" "YES" "$PORTCHK" "$(cat $RUN/bundle2.json | head -c 200)"

echo "== 17. auth refresh: rotating refresh cookie, concurrent refreshes race-free =="
# Two concurrent refreshes present the SAME cookie token (the classic
# multi-tab 401 wave): the first rotates, the loser presents the retired
# token inside the grace window and rotates forward — both must 200 and
# both must yield a working access token. No refresh_token may ever appear
# in a JSON body; the CSRF header is mandatory.
( curl -s -o $RUN/refresh1.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/auth/refresh \
    -b $RUN/cookies.jar -c $RUN/cookies1.jar -H 'X-Requested-With: XMLHttpRequest' > $RUN/r1.code ) & C1=$!
( curl -s -o $RUN/refresh2.json -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/auth/refresh \
    -b $RUN/cookies.jar -c $RUN/cookies2.jar -H 'X-Requested-With: XMLHttpRequest' > $RUN/r2.code ) & C2=$!
# Targeted waits: a bare `wait` also waits for the nats/redis/server/scanner
# daemons (which never exit) and hung the whole suite here.
wait $C1 $C2
R1=$(cat $RUN/r1.code); R2=$(cat $RUN/r2.code)
check "concurrent refresh #1 (cookie)" 200 "$R1" "$(cat $RUN/refresh1.json | head -c 150)"
check "concurrent refresh #2 (retired token inside grace)" 200 "$R2" "$(cat $RUN/refresh2.json | head -c 150)"
check "refresh response carries no refresh_token" "None" "$(python3 -c "import json;print(json.load(open('$RUN/refresh1.json')).get('refresh_token','None'))")"
NEWACCESS=$(jsonget "['access_token']" < $RUN/refresh1.json 2>/dev/null)
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/v1/auth/me -H "Authorization: Bearer $NEWACCESS")
check "renewed access token authenticates" 200 "$code"
NEWACCESS2=$(jsonget "['access_token']" < $RUN/refresh2.json 2>/dev/null)
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/v1/auth/me -H "Authorization: Bearer $NEWACCESS2")
check "racing tab's renewed token authenticates too" 200 "$code"
# CSRF: a cross-site attacker cannot send X-Requested-With.
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8080/api/v1/auth/refresh -b $RUN/cookies.jar)
check "refresh without CSRF header -> 403" 403 "$code"

echo "== 18. vulnerabilities sorting + published window + topology asset click-through =="
# Name sort must be a lexicographic non-decreasing sequence.
code=$(curl -s -o $RUN/vsort.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?sort=cve_id&order=asc" -H "$AUTH")
check "GET /vulnerabilities?sort=cve_id&order=asc" 200 "$code" ""
NAMESORT=$(python3 -c "
import json;d=json.load(open('$RUN/vsort.json'))
ids=[(v.get('cve_id') or '') for v in (d.get('items') or [])]
print('YES' if ids==sorted(ids) and len(ids)>=2 else 'NO')" 2>/dev/null)
check "cve_id asc returns A→Z ordered items" "YES" "$NAMESORT" "$(cat $RUN/vsort.json | head -c 200)"
code=$(curl -s -o $RUN/vpub.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?sort=published_at&order=desc" -H "$AUTH")
check "GET /vulnerabilities?sort=published_at&order=desc" 200 "$code" ""
PUBSORT=$(python3 -c "
import json;d=json.load(open('$RUN/vpub.json'))
ts=[(v.get('published_at') or '') for v in (d.get('items') or []) if v.get('published_at')]
print('YES' if ts==sorted(ts, reverse=True) and len(ts)>=2 else 'NO')" 2>/dev/null)
check "published_at desc returns newest-first" "YES" "$PUBSORT" "$(cat $RUN/vpub.json | head -c 200)"
# Unknown sort keys must degrade to the default order (no 500, no injection).
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?sort=DROP%20TABLE%20vulnerabilities" -H "$AUTH")
check "unknown sort degrades to default (200)" 200 "$code" ""
# Published window filter: a 1970s window matches nothing, a wide one matches all.
code=$(curl -s -o $RUN/vwin.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?published_after=1970-01-01&published_before=1971-01-01" -H "$AUTH")
WIN=$(python3 -c "
import json;d=json.load(open('$RUN/vwin.json'))
print(d.get('total', -1))" 2>/dev/null)
check "published window 1970 matches 0 CVEs" 0 "${WIN:- -1}" ""
code=$(curl -s -o $RUN/vwin2.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities?published_after=2020-01-01" -H "$AUTH")
WIN2=$(python3 -c "
import json;d=json.load(open('$RUN/vwin2.json'))
tot2=d.get('total', -1)
print('YES' if tot2 and tot2>=1 else 'NO')" 2>/dev/null)
check "published_after 2020-01-01 matches seeded CVEs" "YES" "$WIN2" "$(cat $RUN/vwin2.json | head -c 150)"
# Topology asset nodes must expose asset_id for UI click-through (the API
# previously serialized only ref_id, silently breaking the ring + link).
code=$(curl -s -o $RUN/topo3.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/topology?site_id=$SITE_HQ" -H "$AUTH")
check "GET /topology" 200 "$code" ""
ASSETID=$(python3 -c "
import json;d=json.load(open('$RUN/topo3.json'))
nodes=(d.get('nodes') or [])
assets=[n for n in nodes if n.get('kind')=='asset']
print('YES' if assets and all(n.get('asset_id') for n in assets) else 'NO')" 2>/dev/null)
check "asset-kind topology nodes carry asset_id" "YES" "$ASSETID" "$(cat $RUN/topo3.json | head -c 200)"

echo "== 19. CVE affected products + asset rediscover (field-report scenario) =="
# Seed the exact record shape from the field report: OpenSSH affected below
# 10.4 (versionType "custom", start "0", defaultStatus "unaffected"). The
# demo workstation runs OpenSSH 9.6p1 — rediscover must flag it.
cat > $RUN/affected-seed.sql <<'SQL'
INSERT INTO vulnerabilities (cve_id, state, published_at, description, cvss_v3, cwe, source, source_record, affected) VALUES
 ('CVE-2026-99990', 'PUBLISHED', now(), 'e2e: OpenSSH range statement (affected below 10.4, custom ordering).',
  '{"version":"3.1","score":9.8,"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'::jsonb, ARRAY['CWE-787'],
  'cvelistv5', 'CVE-2026-99990',
  '[{"vendor":"OpenBSD","product":"OpenSSH","defaultStatus":"unaffected","versions":[{"version":"0","status":"affected","lessThan":"10.4","versionType":"custom"}]}]'::jsonb)
ON CONFLICT (cve_id) DO NOTHING;
INSERT INTO vulnerability_cpe_matches (id, cve_id, cpe, vendor, product, version, version_start_incl, version_end_excl, version_type)
VALUES (gen_random_uuid(), 'CVE-2026-99990', 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', 'openbsd', 'openssh', '', '0', '10.4', 'custom');
SQL
go -C $ROOT run ./scripts/seedtool "$URL" $RUN/affected-seed.sql > /dev/null 2>&1 || { echo "  AFFECTED SEED FAILED"; }
# 19a. CVE detail returns the affected statement + typed CPE match.
code=$(curl -s -o $RUN/vaff.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/vulnerabilities/CVE-2026-99990" -H "$AUTH")
check "GET /vulnerabilities/CVE-2026-99990" 200 "$code" "$(cat $RUN/vaff.json | head -c 200)"
AFFOK=$(python3 -c "
import json;d=json.load(open('$RUN/vaff.json'))
v=d.get('vulnerability') or {}
aff=v.get('affected') or []
cms=v.get('cpe_matches') or []
ok = len(aff)==1 and aff[0].get('vendor')=='OpenBSD' and aff[0].get('defaultStatus')=='unaffected'
ok = ok and len((aff[0].get('versions') or []))==1 and aff[0]['versions'][0].get('lessThan')=='10.4' and aff[0]['versions'][0].get('versionType')=='custom'
ok = ok and len(cms)==1 and cms[0].get('version_type')=='custom' and cms[0].get('version_start_incl')=='0' and cms[0].get('version_end_excl')=='10.4'
print('YES' if ok else 'NO')")
check "CVE detail carries affected statement + typed cpe_matches" "YES" "$AFFOK" "$(cat $RUN/vaff.json | head -c 400)"
# 19b. Rediscover the OpenSSH workstation: 9.6p1 < 10.4 must create a finding.
ASSET_OSSH=10000000-0000-4000-8000-000000000104
code=$(curl -s -o $RUN/redis.json -w '%{http_code}' -X POST "http://127.0.0.1:8080/api/v1/assets/$ASSET_OSSH/rediscover" -H "$AUTH")
check "POST /assets/:id/rediscover" 200 "$code" "$(cat $RUN/redis.json | head -c 200)"
REDDOK=$(python3 -c "
import json;d=json.load(open('$RUN/redis.json'))
n=d.get('findings_created',-1)
print('YES' if isinstance(n,int) and n>=1 else 'NO')")
check "rediscover created findings (9.6p1 inside <10.4 range)" "YES" "$REDDOK" "$(cat $RUN/redis.json | head -c 200)"
# 19c. The finding exists with CPE_RANGE and points at the seeded CVE.
code=$(curl -s -o $RUN/af.json -w '%{http_code}' "http://127.0.0.1:8080/api/v1/assets/$ASSET_OSSH/findings" -H "$AUTH")
NEWMATCH=$(python3 -c "
import json;d=json.load(open('$RUN/af.json'))
items=d.get('items') or []
hit=[f for f in items if (f.get('cve_id')=='CVE-2026-99990')]
print('YES' if hit and hit[0].get('match_type','').upper() in ('CPE_RANGE','CPERANGE') else 'NO')")
check "asset findings include CVE-2026-99990 (CPE_RANGE)" "YES" "$NEWMATCH" "$(cat $RUN/af.json | head -c 300)"
# 19d. Unknown asset id -> 404.
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:8080/api/v1/assets/00000000-0000-4000-8000-000000000000/rediscover" -H "$AUTH")
check "rediscover unknown asset -> 404" 404 "$code" ""
echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
