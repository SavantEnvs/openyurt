#!/usr/bin/env bash
#
# mayhem/test.sh — BEHAVIORAL oracle for openyurt's iptables-save dump / rule
# parser (pkg/util/iptables/testing/parse.go). Runs the dynamically-linked KAT
# probe (/mayhem/openyurt_iptables_kat, built by build.sh) that drives fixed
# dumps/rules through the REAL ParseIPTablesDump / ParseRule code and asserts
# EXACT behavioral values:
#   - the dump "*filter / :INPUT - [5:10] / -A INPUT ... / COMMIT" parses to one
#     table "filter" with one chain "INPUT" (packets 5, bytes 10) and one rule,
#   - ParseRule("-A INPUT -s 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT") decomposes
#     into chain=INPUT source=10.0.0.0/8 proto=tcp dport=80 jump=ACCEPT,
#   - a leading "!" negates the following value (Negated=true).
# These are documented properties of the parser and match parse_test.go semantics.
#
# Why not `go test` alone (netnew §4): a Go test binary is statically linked, so
# the gate's LD_PRELOAD sabotage shim cannot neuter it — the suite would survive
# sabotage while proving nothing (the cosign/notary false-green). The KAT probe
# is cgo-linked (dynamic), so when the program is neutered to _exit(0) it prints
# nothing, every assertion below misses, and test.sh FAILS — which is the point.
#
# Emits a CTRF summary; exits non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PROBE=/mayhem/openyurt_iptables_kat
passed=0; failed=0

# Unconditional: a missing probe is a build.sh bug — FAIL loudly, never skip.
if [ ! -x "$PROBE" ]; then
  echo "FAIL: KAT probe $PROBE missing or not executable (build.sh should have produced it)" >&2
  emit_ctrf "openyurt-iptables-kat" 0 1
  exit 1
fi

OUT="$("$PROBE" 2>/dev/null)"
echo "--- KAT probe output ---"; printf '%s\n' "$OUT"; echo "------------------------"

# Exact-line assertions (grep -qxF: whole-line, fixed-string).
assert_line() { # <desc> <expected-exact-line>
  if printf '%s\n' "$OUT" | grep -qxF "$2"; then
    echo "PASS: $1"; passed=$((passed+1))
  else
    echo "FAIL: $1 (expected exact line: $2)"; failed=$((failed+1))
  fi
}

assert_line "dump has exactly one table"           "KAT_TABLE_COUNT=1"
assert_line "table name is filter"                 "KAT_TABLE_NAME=filter"
assert_line "table has exactly one chain"          "KAT_CHAIN_COUNT=1"
assert_line "chain name is INPUT"                   "KAT_CHAIN_NAME=INPUT"
assert_line "chain packet counter is 5"            "KAT_PACKETS=5"
assert_line "chain byte counter is 10"             "KAT_BYTES=10"
assert_line "chain has exactly one rule"           "KAT_RULE_COUNT=1"
assert_line "rule chain is INPUT"                   "KAT_RULE_CHAIN=INPUT"
assert_line "rule source is 10.0.0.0/8"            "KAT_RULE_SOURCE=10.0.0.0/8"
assert_line "rule protocol is tcp"                 "KAT_RULE_PROTO=tcp"
assert_line "rule dport is 80"                     "KAT_RULE_DPORT=80"
assert_line "rule jump target is ACCEPT"           "KAT_RULE_JUMP=ACCEPT"
assert_line "negated dest value is 1.2.3.4"        "KAT_NEG_DEST=1.2.3.4"
assert_line "negated dest is flagged Negated=true" "KAT_NEG_NEGATED=true"
assert_line "negated rule jump target is DROP"     "KAT_NEG_JUMP=DROP"

emit_ctrf "openyurt-iptables-kat" "$passed" "$failed"
