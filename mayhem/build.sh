#!/usr/bin/env bash
#
# mayhem/build.sh — build openyurt's iptables-save dump / rule parser
# (pkg/util/iptables/testing/parse.go) as a sanitized libFuzzer binary (OSS-Fuzz
# Go path: go-118-fuzz-build -libfuzzer archive + clang++ ASan link), plus a
# dynamically-linked KAT oracle probe for mayhem/test.sh to run.
#
# Runs inside the commit image (GO mayhem/Dockerfile) as `mayhem` in /mayhem.
# GOROOT/GOPATH/GOMODCACHE are pinned by the Dockerfile ENV under /opt/toolchains
# (absolute, $HOME-independent — so the offline PATCH re-run finds the cache).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (online) fills $GOMODCACHE (go get of the /testing shim).
#   - GOPROXY points at the in-image module cache's file proxy FIRST, network
#     LAST, so the offline re-run resolves entirely from the cache; GOFLAGS=-mod=mod
#     + GOSUMDB=off keep go.sum verification local (no sum.golang.org round trip).
#
# HARNESS STAGING (netnew §6 Go / port-go): openyurt's real module pins go 1.25.0
# and drags the entire Kubernetes + cloud closure (apimachinery, client-go,
# controller-runtime, aliyun sdk, edgex…) through go.mod. The iptables-save
# parser in pkg/util/iptables/testing/parse.go needs only stdlib + TWO symbols
# (the `Table`/`Chain` string types) from openyurt's own pkg/util/iptables. So we
# copy JUST parse.go into a fresh STANDALONE Go mini-module at
# _mayhem_harness/iptables, rename its package, repoint its one non-stdlib import
# at a tiny local `iptables` shim (just those two string types), and build there.
# The module's only downloaded dep is the go-118-fuzz-build /testing shim (which
# transitively provides go-fuzz-headers) — openyurt's giant graph is never
# touched. The staging dir is leading-underscore so `go build/test ./...`
# wildcards skip it and it can never disturb the upstream suite.
set -euo pipefail

: "${SRC:=/mayhem}"

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

# Sanitizers (§6.1): the OSS-Fuzz Go path is ASan-only for the libFuzzer link.
# Honor the knob — an explicit empty SANITIZER_FLAGS yields an un-sanitized build.
: "${SANITIZER_FLAGS=-fsanitize=address}"
export SANITIZER_FLAGS
GO_SAN="-fsanitize=address"
[ -n "${SANITIZER_FLAGS}" ] || GO_SAN=""

# Debug-info contract (§6.2 item 10): gc always emits DWARF4 with no knob, so we
# force the clang-compiled cgo C shims to DWARF3 (CGO_CFLAGS/CGO_CXXFLAGS) AND
# prepend a DWARF3 anchor.o at the final clang++ link so the FIRST .debug_info CU
# (what the gate reads) is DWARF < 4. $GO_DEBUG_FLAGS threads any base pins.
export GO_DEBUG_FLAGS="${GO_DEBUG_FLAGS:--gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:-} ${GO_DEBUG_FLAGS}"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:-} ${GO_DEBUG_FLAGS}"

# Resolve modules offline-first from the in-image cache; network only as fallback.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOSUMDB="${GOSUMDB:-off}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"

go version

TARGET="fuzz_parse"
STAGE="$SRC/_mayhem_harness/iptables"
MODPATH="openyurt.local/mayhemiptables"
UPSTREAM_IMPORT="github.com/openyurtio/openyurt/pkg/util/iptables"

# Pseudo-version of the go-118-fuzz-build /testing shim that the Dockerfile's
# `go install ...@a70c2aa677fa...` already resolved + cached. A raw commit hash
# forces a proxy.golang.org round trip to resolve it — fatal on the air-gapped
# PATCH re-run; the pseudo-version resolves straight from the file cache.
GO118_SHIM_VERSION="v0.0.0-20250520111509-a70c2aa677fa"

# ── Stage a standalone mini-module: parse.go (verbatim) + shim + harness + KAT ──
rm -rf "$STAGE"
mkdir -p "$STAGE/iptables" "$STAGE/kat"

# parse.go copied verbatim EXCEPT: rename its `package testing` clause to
# `package iptparse` (so the harness/KAT live in the same package), and repoint
# ONLY its openyurt pkg/util/iptables import at the local shim (same package name
# `iptables`, so all `iptables.Table`/`iptables.Chain` uses are untouched).
sed -e 's#^package testing$#package iptparse#' \
    -e "s#$UPSTREAM_IMPORT#$MODPATH/iptables#" \
    "$SRC/pkg/util/iptables/testing/parse.go" > "$STAGE/parse.go"
grep -q "^package iptparse$" "$STAGE/parse.go" \
  || { echo "FATAL: package rename failed in staged parse.go"; exit 1; }
grep -q "$MODPATH/iptables" "$STAGE/parse.go" \
  || { echo "FATAL: iptables import rewrite failed in staged parse.go"; exit 1; }
! grep -q "$UPSTREAM_IMPORT\"" "$STAGE/parse.go" \
  || { echo "FATAL: upstream iptables import still present in staged parse.go"; exit 1; }

cp "$SRC/mayhem/iptables_shim.go.src" "$STAGE/iptables/iptables.go"
cp "$SRC/mayhem/harness_parse.go.src" "$STAGE/harness_parse.go"
cp "$SRC/mayhem/kat_export.go.src"    "$STAGE/kat_export.go"
cp "$SRC/mayhem/kat/main.go"          "$STAGE/kat/main.go"

# ── Module graph: init, add the /testing shim, then tidy ───────────────────────
(
  cd "$STAGE"
  go mod init "$MODPATH"
  # The /testing shim pulls go-fuzz-headers transitively; both resolve from the
  # file-proxy cache offline on the PATCH re-run.
  go get "github.com/AdamKorcz/go-118-fuzz-build/testing@${GO118_SHIM_VERSION}"
  go mod tidy
)

# ── Build the libFuzzer archive from the staged mini-module ────────────────────
mkdir -p "$SRC/mayhem-build"
echo "=== go-118-fuzz-build $TARGET (func FuzzParse) ==="
(
  cd "$STAGE"
  go-118-fuzz-build -func FuzzParse -o "$SRC/mayhem-build/$TARGET.a" .
)

# ── DWARF3 anchor FIRST, then clang++ ASan+fuzzer link ─────────────────────────
printf 'int __mayhem_dwarf3_anchor;\n' > "$SRC/mayhem-build/anchor.c"
$CC $GO_DEBUG_FLAGS -c "$SRC/mayhem-build/anchor.c" -o "$SRC/mayhem-build/anchor.o"
# Init-ordering shim (go_runtime_ready.c, #1644): linked FIRST so libFuzzer waits for Go's runtime.
SHIM_O="$SRC/mayhem-build/go_runtime_ready.o"
$CC $GO_DEBUG_FLAGS -c "$SRC/mayhem/go_runtime_ready.c" -o "$SHIM_O"
$CXX $GO_SAN $LIB_FUZZING_ENGINE \
     "$SRC/mayhem-build/anchor.o" "$SHIM_O" "$SRC/mayhem-build/$TARGET.a" -o "/mayhem/$TARGET"
echo "built /mayhem/$TARGET"

# ── KAT oracle probe: dynamically-linked (cgo) so the sabotage shim can neuter it ─
export CGO_ENABLED=1
(
  cd "$STAGE"
  go build -o /mayhem/openyurt_iptables_kat ./kat
)
file /mayhem/openyurt_iptables_kat | grep -q 'dynamically linked' \
  || { echo "FATAL: /mayhem/openyurt_iptables_kat is not dynamically linked — oracle would be reward-hackable"; exit 1; }
echo "built /mayhem/openyurt_iptables_kat (dynamically linked)"

echo "build.sh complete"
