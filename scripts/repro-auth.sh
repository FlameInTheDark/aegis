#!/usr/bin/env bash
# Production auth lifecycle verification (cookie-based rotating refresh
# tokens, v1.2.8 architecture):
#   1. login sets an HttpOnly + SameSite refresh cookie and does NOT put a
#      refresh token in the JSON body
#   2. expired access tokens 401 (never 403/500) and silent refresh works
#   3. /auth/refresh is cookie-authenticated and CSRF-guarded
#      (X-Requested-With required; a cross-site form cannot send it)
#   4. every refresh ROTATES the token; a retired token presented inside
#      the grace window still works (multi-tab race), beyond it the whole
#      session family is revoked (reuse detection)
#   5. logout revokes server-side and clears the cookie
#   6. 30-way concurrent refresh storm: zero 5xx, zero logouts
#   7. server-side vuln sorting + streamed report download still work
set -uo pipefail

ROOT=/home/z/my-project
INFRA=$ROOT/scripts/sandbox-infra
PGT=/tmp/my-project/scripts/pgtest
RUN=/tmp/aegis-auth
mkdir -p $RUN
export PATH=$PATH:$PGT/bin:/home/z/go-sdk/go/bin

cleanup() {
  [ -n "${SRV_PID:-}" ] && kill $SRV_PID 2>/dev/null
  [ -n "${NATS_PID:-}" ] && kill $NATS_PID 2>/dev/null
  [ -n "${RDS_PID:-}" ] && kill $RDS_PID 2>/dev/null
  [ -n "${S3_PID:-}" ] && kill $S3_PID 2>/dev/null
  $PGT/bin/pg_ctl -D $PGT/data-e2e -m fast stop >/dev/null 2>&1
}
trap cleanup EXIT

jsonget() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }
PASS=0; FAIL=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS: $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL: $1 expected $2 got $3"; FAIL=$((FAIL+1)); fi
}
XHR='X-Requested-With: XMLHttpRequest'

# do_login JARFILE VARBASE: fresh login; sets ${VARBASE}_AT (access token)
# and leaves the refresh cookie in JARFILE. Echoes nothing.
do_login() {
  local jar="$1" var="$2" hdr body
  hdr=$(curl -s -D - -c "$jar" -o "$RUN/login-body.json" -X POST $BASE/auth/login \
    -H 'Content-Type: application/json' -H "$XHR" \
    -d '{"email":"admin@aegis.local","password":"aegis-demo-admin-2026"}')
  printf '%s' "$hdr" > "$RUN/login-headers.txt"
  eval "${var}_AT=\$(jsonget '[\"access_token\"]' < $RUN/login-body.json)"
}

echo "== 1. infrastructure =="
$PGT/bin/pg_ctl -D $PGT/data-e2e -o "-p 5432 -k $PGT/sock -c listen_addresses=127.0.0.1" -l $RUN/pg.log restart >/dev/null 2>&1 || \
$PGT/bin/pg_ctl -D $PGT/data-e2e -o "-p 5432 -k $PGT/sock -c listen_addresses=127.0.0.1" -l $RUN/pg.log start >/dev/null 2>&1
for i in $(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/5432) 2>/dev/null && break; sleep 0.5; done
$INFRA/bin/nats-server -js -a 127.0.0.1 -p 4222 -store_dir $RUN/nats > $RUN/nats.log 2>&1 &
NATS_PID=$!
$INFRA/bin/redis-stub > $RUN/redis.log 2>&1 &
RDS_PID=$!
sleep 1
echo "  postgres + nats + redis-stub up"

echo "== 2. migrations + seed =="
URL="postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable"
go -C $ROOT run ./scripts/seedtool "$URL" $ROOT/scripts/sandbox-infra/reset.sql >/dev/null 2>&1
AEGIS_DATABASE_URL="$URL" go -C $ROOT run ./scripts/migrate > $RUN/migrate.log 2>&1 || { echo "MIGRATE FAILED"; cat $RUN/migrate.log; exit 1; }
go -C $ROOT run ./scripts/seedtool "$URL" $ROOT/scripts/seed/demo.sql > $RUN/seed.log 2>&1 || { echo "SEED FAILED"; tail -5 $RUN/seed.log; exit 1; }
echo "  migrations + seed applied"

echo "== 3. boot server: 5s access TTL, 3s rotation grace, insecure demo cookie =="
go -C $ROOT build -ldflags "-s -w -X main.version=$(cat $ROOT/VERSION 2>/dev/null || echo dev)" -o $RUN/aegis-server ./cmd/server || exit 1
python3 $ROOT/scripts/sandbox-infra/s3-stub.py 9002 > $RUN/s3.log 2>&1 &
S3_PID=$!
AEGIS_ENV=development \
AEGIS_LOG_LEVEL=info \
AEGIS_DATABASE_URL="$URL" \
AEGIS_REDIS_URL=redis://127.0.0.1:6379/0 \
AEGIS_NATS_URL=nats://127.0.0.1:4222 \
AEGIS_JWT_SECRET=e2e-secret-key-0123456789abcdef0123456789abcdef \
AEGIS_BOOTSTRAP_ADMIN_EMAIL=admin@aegis.local \
AEGIS_BOOTSTRAP_ADMIN_PASSWORD=aegis-demo-admin-2026 \
AEGIS_ACCESS_TOKEN_TTL=5s \
AEGIS_REFRESH_ROTATION_GRACE=3s \
AEGIS_AUTH_COOKIE_SECURE=false \
AEGIS_S3_ENDPOINT=http://127.0.0.1:9002 \
AEGIS_DEMO_MODE=true \
$RUN/aegis-server > $RUN/server.log 2>&1 &
SRV_PID=$!
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 0.5
done
[ "$code" = "200" ] || { echo "SERVER NEVER HEALTHY"; tail -40 $RUN/server.log; exit 1; }
echo "  server up"

BASE=http://127.0.0.1:8080/api/v1

echo "== 4. login sets the refresh cookie, body carries no refresh token =="
do_login $RUN/jar A
AT=$A_AT
check "login issues access token" ok "$([ -n "$AT" ] && [ "$AT" != "None" ] && echo ok || echo missing)"
RT_IN_BODY=$(python3 -c "import json;print(json.load(open('$RUN/login-body.json')).get('refresh_token','None'))")
check "login body has NO refresh_token" "None" "$RT_IN_BODY"
COOKIE_LINE=$(grep -i '^set-cookie:' $RUN/login-headers.txt | head -1)
echo "$COOKIE_LINE" | grep -q 'aegis_rt=' && check "refresh cookie set (aegis_rt)" ok ok || check "refresh cookie set (aegis_rt)" ok "missing: $COOKIE_LINE"
echo "$COOKIE_LINE" | grep -qi 'HttpOnly' && check "cookie HttpOnly" ok ok || check "cookie HttpOnly" ok missing
echo "$COOKIE_LINE" | grep -qi 'SameSite=lax' && check "cookie SameSite=Lax" ok ok || check "cookie SameSite=Lax" ok missing
echo "$COOKIE_LINE" | grep -qi 'Path=/' && check "cookie Path=/" ok ok || check "cookie Path=/" ok missing
echo "$COOKIE_LINE" | grep -qi 'Secure' && check "cookie NOT Secure in dev (http demo)" ok "unexpected Secure flag" || check "cookie NOT Secure in dev (http demo)" ok ok

check "me with fresh token" 200 "$(curl -s -o /dev/null -w '%{http_code}' $BASE/auth/me -H "Authorization: Bearer $AT")"

echo "== 5. expiry → 401, CSRF guard, silent refresh rotates =="
sleep 6
check "me with expired token" 401 "$(curl -s -o /dev/null -w '%{http_code}' $BASE/auth/me -H "Authorization: Bearer $AT")"
check "refresh WITHOUT CSRF header -> 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar)"
check "refresh with EMPTY cookie jar -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -H "$XHR")"

cp $RUN/jar $RUN/jar-t1   # keep the pre-rotation token for the grace test
RCODE=$(curl -s -o $RUN/refresh1.json -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar -c $RUN/jar -H "$XHR")
check "refresh with valid cookie" 200 "$RCODE"
AT2=$(jsonget '["access_token"]' < $RUN/refresh1.json 2>/dev/null)
check "renewed access token authenticates" 200 "$(curl -s -o /dev/null -w '%{http_code}' $BASE/auth/me -H "Authorization: Bearer $AT2")"
T1=$(awk '$6=="aegis_rt" {print $7}' $RUN/jar-t1)
T2=$(awk '$6=="aegis_rt" {print $7}' $RUN/jar)
[ -n "$T1" ] && [ -n "$T2" ] && [ "$T1" != "$T2" ] && check "refresh ROTATED the token" ok ok || check "refresh ROTATED the token" ok "unchanged/missing"

echo "== 6. multi-tab race: retired token inside grace still works =="
RCODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar-t1 -c $RUN/jar-t1 -H "$XHR")
check "retired token refresh within grace" 200 "$RCODE"

echo "== 7. reuse detection: retired token beyond grace revokes the family =="
sleep 4   # grace is 3s in this deployment
check "retired token refresh beyond grace" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar -H "$XHR")"
check "family revoked: even the newest token is dead" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar-t1 -H "$XHR")"

echo "== 8. garbage cookie =="
echo '.aegis.local      FALSE   /       FALSE   0       aegis_rt        garbage-value' > $RUN/jar-garbage
check "refresh with garbage cookie" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar-garbage -H "$XHR")"

echo "== 9. logout revokes server-side + clears the cookie =="
do_login $RUN/jar3 B
AT3=$B_AT
check "logout WITHOUT CSRF header -> 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/logout -b $RUN/jar3)"
LCODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/logout -b $RUN/jar3 -c $RUN/jar3 -H "$XHR")
check "logout with CSRF header" 204 "$LCODE"
check "refresh after logout" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar3 -H "$XHR")"
CLEARCookie=$(curl -s -D - -o /dev/null -X POST $BASE/auth/logout -b $RUN/jar3 -H "$XHR" | grep -i '^set-cookie:' | head -1)
echo "$CLEARCookie" | grep -qi 'httponly' && check "logout clears the cookie" ok ok || check "logout clears the cookie" ok missing

echo "== 10. multi-tab refresh storm (30 concurrent, zero 5xx, zero logouts) =="
do_login $RUN/jar-storm C
for i in $(seq 1 30); do cp $RUN/jar-storm $RUN/jar-storm-$i; done
TALLY=$(for i in $(seq 1 30); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/auth/refresh -b $RUN/jar-storm-$i -c $RUN/jar-storm-$i -H "$XHR" &
done | sort | uniq -c | tr '\n' ' ')
echo "  status tally: $TALLY"
STORM_500=$(echo "$TALLY" | tr ' ' '\n' | grep -c "^500$" || true)
STORM_401=$(echo "$TALLY" | tr ' ' '\n' | grep -c "^401$" || true)
check "no 500s during refresh storm" 0 "$STORM_500"
check "no logouts during refresh storm" 0 "$STORM_401"
check "session still alive after storm" 200 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/auth/refresh -b $RUN/jar-storm -c $RUN/jar-storm -H "$XHR")"
rm -f $RUN/jar-storm-*

echo "== 11. vuln sort param honored server-side =="
do_login $RUN/jar-sort D
sortcheck() {
  curl -s "$BASE/vulnerabilities?sort=$1&order=$2&limit=10" -H "Authorization: Bearer $D_AT" | python3 -c "
import json,sys
resp=json.load(sys.stdin)
items=resp.get('items')
if items is None:
    print('no-items: '+json.dumps(resp)[:120]); raise SystemExit
if not items:
    print('no-data'); raise SystemExit
dates=[i['published_at'] for i in items if i.get('published_at')]
keys={'desc': lambda ds: ds==sorted(ds,reverse=True), 'asc': lambda ds: ds==sorted(ds)}['$2']
print('ok' if keys(dates) else 'unordered')"
}
check "sort=published_at desc returns descending dates" ok "$(sortcheck published_at desc)"
check "sort=published_at asc returns ascending dates" ok "$(sortcheck published_at asc)"
check "sort=cvss_score desc returns descending scores" ok "$(
  curl -s "$BASE/vulnerabilities?sort=cvss_score&order=desc&limit=10" -H "Authorization: Bearer $D_AT" | python3 -c "
import json,sys
resp=json.load(sys.stdin)
items=resp.get('items')
if items is None:
    print('no-items: '+json.dumps(resp)[:120]); raise SystemExit
if not items:
    print('no-data'); raise SystemExit
s=[i['cvss_score'] for i in items]
print('ok' if s==sorted(s,reverse=True) else 'unordered')")"

ORG="00000000-0000-4000-8000-000000000001"
JOB="00000000-0000-4000-8000-000000000910"
cat > $RUN/report-seed.sql <<EOF
INSERT INTO reports (id, organization_id, name, type, format, created_by)
VALUES ('00000000-0000-4000-8000-000000000900', '$ORG', 'E2E Executive demo', 'executive_security', 'html',
        '00000000-0000-4000-8000-0000000000c1')
ON CONFLICT (id) DO NOTHING;
INSERT INTO report_jobs (id, definition_id, organization_id, state, progress, artifact_key, size_bytes)
VALUES ('$JOB', '00000000-0000-4000-8000-000000000900', '$ORG', 'completed', 100,
        'reports/$ORG/$JOB.html', 78)
ON CONFLICT (id) DO NOTHING;
EOF
go -C $ROOT run ./scripts/seedtool "$URL" $RUN/report-seed.sql >/dev/null 2>&1 && echo "  report job seeded"

echo "== 12. report download (streamed through the API) =="
check "download without token" 401 "$(curl -s -o /dev/null -w '%{http_code}' $BASE/reports/jobs/$JOB/download)"
check "download unknown job" 404 "$(curl -s -o /dev/null -w '%{http_code}' $BASE/reports/jobs/00000000-0000-4000-8000-000000000999/download -H "Authorization: Bearer $D_AT")"
HDR=$(curl -s -D - -o $RUN/report.html "$BASE/reports/jobs/$JOB/download" -H "Authorization: Bearer $D_AT")
check "download completed job" 200 "$(echo "$HDR" | head -1 | awk '{print $2}')"
echo "$HDR" | grep -qi 'Content-Disposition: attachment' && check "attachment disposition" ok ok || check "attachment disposition" ok missing
BODY_OK=$(grep -c "ok-e2e-artifact" $RUN/report.html 2>/dev/null || true)
check "artifact bytes streamed" 1 "$BODY_OK"
FNAME=$(echo "$HDR" | grep -i 'Content-Disposition' | sed 's/.*filename="\([^"]*\)".*/\1/')
echo "  filename: $FNAME"
case "$FNAME" in
  aegis-report-executive_security-*.html) check "friendly filename" ok ok ;;
  *) check "friendly filename" ok "$FNAME" ;;
esac

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
