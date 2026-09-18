#!/bin/sh
# In-container traceroute capability verification for the Aegis scanner.
# Built into the scanner image (/usr/local/bin/verify-traceroute); run with:
#
#   docker compose exec scanner verify-traceroute
#   # or, without compose:
#   docker run --rm --cap-add NET_RAW --cap-drop ALL <scanner-image> verify-traceroute
#
# Checks, in order:
#   1. the container's effective capabilities (NET_RAW must be present),
#   2. file capabilities on the nmap/traceroute binaries,
#   3. the container's routing view (`ip route`),
#   4. live traceroutes: UDP (default), ICMP (-I), TCP/443 (-T -p 443),
#      and tracepath (UDP, unprivileged), with plain-language verdicts
#      (TCP/443 destination reached? nmap traceroute XML emitted?).
# Exit code is 0 when the tooling is in place; probe results depend on the
# surrounding network (NATs that swallow ICMP Time Exceeded show partial
# paths — that is an environment property, not a broken install).
set -u

fail=0
say() { printf '\n== %s ==\n' "$1"; }

say "capabilities (CapEff)"
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
if command -v capsh >/dev/null 2>&1; then
    capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}') 2>/dev/null | head -2
fi
case "$(grep CapEff /proc/self/status | awk '{print $2}')" in
    *000000200*|*00000000200*) : ;; # cap_net_raw = bit 13 (0x2000)
    *) echo "WARN: cap_net_raw not visibly set in CapEff hex above (bit 13 = 0x2000)";;
esac

say "tools"
for t in nmap traceroute tracepath ip; do
    if command -v "$t" >/dev/null 2>&1; then
        printf '%-11s %s\n' "$t" "$(command -v $t)"
    else
        printf '%-11s MISSING\n' "$t"
        [ "$t" = "tracepath" ] || fail=1
    fi
done

say "file capabilities"
getcap /usr/bin/nmap /usr/bin/traceroute 2>/dev/null || echo "getcap unavailable (libcap missing)"

say "ip route"
ip route 2>/dev/null || echo "ip unavailable"

say "traceroute UDP (default probes, port 53 + high ports)"
traceroute -n -U -p 53 -w 2 -q 1 -m 10 1.1.1.1 2>&1 || true

say "traceroute ICMP (-I)"
traceroute -n -I -w 2 -q 1 -m 10 1.1.1.1 2>&1 || true

say "traceroute TCP/443 (-T -p 443)"
tcp443=$(traceroute -n -T -p 443 -w 2 -q 1 -m 10 1.1.1.1 2>&1) || true
printf '%s\n' "$tcp443"
if printf '%s\n' "$tcp443" | grep -qE '^[[:space:]]*[0-9]+[[:space:]]+1\.1\.1\.1([[:space:]]|$)'; then
    echo "OK: TCP/443 reached the target — the scanner's TCP-first traceroute ladder produces usable paths here."
else
    echo "NOTE: TCP/443 did not reach the target from this network. The scanner records honest partial paths; blocked/unresponsive hops are never reported as 'no route'."
fi

say "tracepath (UDP, no raw sockets needed)"
tracepath -n -m 10 1.1.1.1 2>&1 || true

say "nmap traceroute smoke test (TCP SYN probes)"
nmap_smoke=$(nmap -sn -PS443 --traceroute -n --host-timeout 60s -oX - 1.1.1.1 2>&1) || true
printf '%s\n' "$nmap_smoke" | grep -E '<hop|<trace' | head -12 || true
case "$nmap_smoke" in
    *"<trace"*|*"<hop"*) : ;;
    *) echo "NOTE: nmap emitted no traceroute XML; first lines of its output:"
       printf '%s\n' "$nmap_smoke" | head -5 ;;
esac

printf '\n%s\n' "Done. Partial paths (* * * middle hops) inside Docker Desktop/WSL2 NAT are expected — see docs/DEVELOPMENT.md 'Traceroute from containers'. On a Linux host run the scanner with network_mode: host for full WAN hop visibility."
exit $fail
