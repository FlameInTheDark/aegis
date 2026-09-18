#!/usr/bin/env python3
"""Patch internal/scanning/scope.go: accept IP ranges in the CIDR list,
expand them to CIDR blocks (rangeToCIDRs) so nmap gets valid targets."""
import sys

PATH = "/home/z/my-project/internal/scanning/scope.go"
src = open(PATH).read()

old_loops = (
    "\tfor _, c := range cidrs {\n"
    "\t\tc = strings.TrimSpace(c)\n"
    '\t\tif c == "" {\n'
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\tif err := check(c); err != nil {\n"
    "\t\t\tv.Errors = append(v.Errors, err.Error())\n"
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\tadd(c)\n"
    "\t}\n"
    "\tfor _, r := range ipRanges {\n"
    "\t\tlo, hi, err := parseRange(r)\n"
    "\t\tif err != nil {\n"
    "\t\t\tv.Errors = append(v.Errors, err.Error())\n"
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\tn := ipRangeSize(lo, hi) + 1\n"
    "\t\tif n < 0 {\n"
    '\t\t\tv.Errors = append(v.Errors, fmt.Sprintf("invalid range %q: end before start", r))\n'
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\tv.TotalAddresses += n\n"
    "\t\tif isPublic(lo) && !allowPublic {\n"
    '\t\t\tv.Errors = append(v.Errors, fmt.Sprintf("%s contains public addresses; public scanning is disabled", r))\n'
    "\t\t}\n"
    "\t\tadd(r)\n"
    "\t}\n"
)

new_loops = (
    '\t\t// processRange validates one "start-end" range (full IPs or last-octet\n'
    "\t\t// shorthand) and expands it into CIDR blocks. Ranges arrive mixed into\n"
    "\t\t// the CIDR list because users type them into the same scan-form field;\n"
    "\t\t// the expansion keeps every downstream consumer uniform (nmap argv\n"
    '\t\t// cannot parse "ip-ip" pairs, denylist math is CIDR-based, and scope\n'
    "\t\t// storage stays canonical).\n"
    "\t\tprocessRange := func(r string) {\n"
    "\t\t\tlo, hi, err := parseRange(r)\n"
    "\t\t\tif err != nil {\n"
    "\t\t\t\tv.Errors = append(v.Errors, err.Error())\n"
    "\t\t\t\treturn\n"
    "\t\t\t}\n"
    "\t\t\tn := ipRangeSize(lo, hi) + 1\n"
    "\t\t\tif n < 0 {\n"
    '\t\t\t\tv.Errors = append(v.Errors, fmt.Sprintf("invalid range %q: end before start", r))\n'
    "\t\t\t\treturn\n"
    "\t\t\t}\n"
    "\t\t\tv.TotalAddresses += n\n"
    "\t\t\tif isPublic(lo) && !allowPublic {\n"
    '\t\t\t\tv.Errors = append(v.Errors, fmt.Sprintf("%s contains public addresses; public scanning is disabled", r))\n'
    "\t\t\t}\n"
    "\t\t\tfor _, c := range rangeToCIDRs(lo, hi) {\n"
    "\t\t\t\tadd(c)\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\n"
    "\tfor _, c := range cidrs {\n"
    "\t\tc = strings.TrimSpace(c)\n"
    '\t\tif c == "" {\n'
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\t// Range-looking entries are tried as ranges first: anything that\n"
    "\t\t// parses as start-end must never reach the CIDR parser, which\n"
    '\t\t// would reject it with "invalid CIDR or IP ...; scope is empty".\n'
    '\t\tif strings.Contains(c, "-") {\n'
    "\t\t\tif _, _, perr := parseRange(c); perr == nil {\n"
    "\t\t\t\tprocessRange(c)\n"
    "\t\t\t\tcontinue\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t\tif err := check(c); err != nil {\n"
    "\t\t\tv.Errors = append(v.Errors, err.Error())\n"
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\tadd(c)\n"
    "\t}\n"
    "\tfor _, r := range ipRanges {\n"
    "\t\tr = strings.TrimSpace(r)\n"
    '\t\tif r == "" {\n'
    "\t\t\tcontinue\n"
    "\t\t}\n"
    "\t\tprocessRange(r)\n"
    "\t}\n"
)

if old_loops not in src:
    sys.exit("FAIL: cidrs/ipRanges loop block not found verbatim")
src = src.replace(old_loops, new_loops, 1)

anchor = "func inc(ip net.IP) {"
if anchor not in src:
    sys.exit("FAIL: inc() anchor not found")
helpers = """// rangeToCIDRs decomposes an arbitrary inclusive IP range into the minimal
// list of CIDR blocks covering it (the standard "range to CIDR" split).
// nmap's argv accepts CIDRs and octet shorthand but not "ip-ip" pairs, and
// canonical CIDRs keep scope storage and denylist math uniform. IPv4 and
// IPv6 ranges are both handled; a full-space range collapses to one block.
func rangeToCIDRs(lo, hi net.IP) []string {
\tif lo == nil || hi == nil {
\t\treturn nil
\t}
\tv4 := lo.To4() != nil && hi.To4() != nil
\tl := append([]byte(nil), lo.To16()...)
\th := append([]byte(nil), hi.To16()...)
\tvar out []string
\tfor bytes.Compare(l, h) <= 0 {
\t\thostBits := 0
\t\tfor hostBits < 128 &&
\t\t\tlowBitsZero(l, hostBits+1) &&
\t\t\tbytes.Compare(orLowBits(l, hostBits+1), h) <= 0 {
\t\t\thostBits++
\t\t}
\t\tprefix := 128 - hostBits
\t\tip := l
\t\tif v4 {
\t\t\tip = l[12:]
\t\t\tprefix -= 96
\t\t}
\t\tout = append(out, net.IP(ip).String()+"/"+strconv.Itoa(prefix))
\t\tif hostBits >= 128 {
\t\t\tbreak
\t\t}
\t\tl = addPow2(l, hostBits)
\t}
\treturn out
}

// lowBitsZero reports whether the lowest n bits of the 16-byte big-endian
// address are all zero (block alignment check).
func lowBitsZero(b []byte, n int) bool {
\tif n <= 0 {
\t\treturn true
\t}
\tif n > 128 {
\t\treturn false
\t}
\tfull := n / 8
\tfor i := 16 - full; i < 16; i++ {
\t\tif b[i] != 0 {
\t\t\treturn false
\t\t}
\t}
\tif rem := n % 8; rem > 0 {
\t\tif mask := byte(1<<uint(rem)) - 1; b[16-full-1]&mask != 0 {
\t\t\treturn false
\t\t}
\t}
\treturn true
}

// orLowBits returns b with its lowest n bits set - the last address of the
// aligned block starting at b (b must be aligned for n bits).
func orLowBits(b []byte, n int) []byte {
\tout := append([]byte(nil), b...)
\tif n <= 0 {
\t\treturn out
\t}
\tif n >= 128 {
\t\tfor i := range out {
\t\t\tout[i] = 0xff
\t\t}
\t\treturn out
\t}
\tfull := n / 8
\tfor i := 16 - full; i < 16; i++ {
\t\tout[i] = 0xff
\t}
\tif rem := n % 8; rem > 0 {
\t\tout[16-full-1] |= byte(1<<uint(rem)) - 1
\t}
\treturn out
}

// addPow2 returns b + 2^n. The address is expected to be aligned for n bits
// (low n bits zero), so the addition cannot carry into or below bit n.
func addPow2(b []byte, n int) []byte {
\tout := append([]byte(nil), b...)
\tif n >= 128 {
\t\tfor i := range out {
\t\t\tout[i] = 0
\t\t}
\t\treturn out
\t}
\tidx := 15 - n/8
\tout[idx] |= byte(1) << uint(n%8)
\treturn out
}

"""
src = src.replace(anchor, helpers + anchor, 1)

old_imp = 'import (\n\t"fmt"\n\t"net"\n\t"strconv"\n\t"strings"\n)'
new_imp = 'import (\n\t"bytes"\n\t"fmt"\n\t"net"\n\t"strconv"\n\t"strings"\n)'
if old_imp not in src:
    sys.exit("FAIL: import block not found")
src = src.replace(old_imp, new_imp, 1)

open(PATH, "w").write(src)
print("OK scope.go patched")
