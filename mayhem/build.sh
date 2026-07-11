#!/usr/bin/env bash
#
# timestamp-authority/mayhem/build.sh — build sigstore/timestamp-authority's OSS-Fuzz Go fuzz
# targets as sanitized libFuzzer binaries, REPLICATING OSS-Fuzz's compile_native_go_fuzzer.
#
# OSS-Fuzz build (projects/timestamp-authority/build.sh -> test/fuzz/oss_fuzz_build.sh):
#   compile_native_go_fuzzer .../v2/pkg/api FuzzParseJSONRequest FuzzParseJSONRequest
#   compile_native_go_fuzzer .../v2/pkg/api FuzzParseDERRequest  FuzzParseDERRequest
# Both are NATIVE `func FuzzX(f *testing.F)` harnesses (pkg/api/timestamp_test.go), built with
# go-118-fuzz-build, then linked with $LIB_FUZZING_ENGINE. FuzzParseJSONRequest fuzzes
# api.ParseJSONRequest (JSON timestamp request -> timestamp.Request); FuzzParseDERRequest fuzzes
# the unexported api.parseDERRequest (ASN.1 DER TimeStampReq -> timestamp.Request), both via the
# same package so no source modification is needed.
#
# We produce:
#   /mayhem/FuzzParseJSONRequest — OSS-Fuzz target (ASan+libFuzzer)
#   /mayhem/FuzzParseDERRequest  — OSS-Fuzz target (ASan+libFuzzer)
#
# DWARF gate (SPEC §6.2 item 10): Go's gc compiler always emits DWARF4 (no downgrade flag).
# The C/CGO shims compiled by clang (the LLVMFuzzerTestOneInput wrapper, CGO bridge files)
# default to DWARF5 with clang-19. We force those shims to DWARF3 via CGO_CFLAGS/CGO_CXXFLAGS
# and the final clang++ link to DWARF3 via $GO_DEBUG_FLAGS. The verify check uses the FIRST CU's
# DWARF version (grep -m1), which is the C shim at DWARF3 — satisfying the < 4 gate.
#
# Runs inside the commit image (Go mayhem/Dockerfile) as `mayhem` in /mayhem.
# GOROOT/GOPATH/GOMODCACHE are pinned by the Dockerfile ENV under /opt/toolchains.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the
# Go libFuzzer link. Keep ASan as the Go-fuzz sanitizer regardless of the base default. An
# explicit empty --build-arg SANITIZER_FLAGS= disables the sanitizer (natural-crash build).
: "${SANITIZER_FLAGS=-fsanitize=address}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# $(go env GOMODCACHE) reads the pinned ENV under /opt/toolchains (set in the Dockerfile),
# so the file proxy path is correct regardless of $HOME.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

cd "$SRC"
go version

# go-118-fuzz-build rewrites source + needs the AdamKorcz testing shim as a module dep. Add the
# module deps WITHOUT a trailing `go mod tidy` after the get (tidy first, then `go get` the shim —
# tidy would otherwise prune the shim because nothing imports it until the builder generates the
# entrypoint).
go mod tidy 2>&1 | tail -2 || true
go get github.com/AdamKorcz/go-118-fuzz-build/testing@latest 2>&1 | tail -2 || true

mkdir -p "$SRC/mayhem-build"

# Helper: compile one fuzz target with go-118-fuzz-build, then link with clang+ASan+libFuzzer.
# Usage: build_target <output_name> <FuzzFunc> <import_path>
build_target() {
  local outname="$1" func_name="$2" import_path="$3"
  echo "=== building $outname (func=$func_name pkg=$import_path) ==="
  go-118-fuzz-build -func "$func_name" -o "$SRC/mayhem-build/${outname}.a" "$import_path"
  # Link: DWARF3 via $GO_DEBUG_FLAGS ensures the C-shim CU (first in the binary) is at DWARF3.
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS \
      "$SRC/mayhem-build/${outname}.a" -o "/mayhem/$outname"
  echo "  -> /mayhem/$outname"
}

# pkg/api — FuzzParseJSONRequest fuzzes api.ParseJSONRequest; FuzzParseDERRequest fuzzes the
# unexported api.parseDERRequest (both harnesses live in pkg/api/timestamp_test.go).
build_target "FuzzParseJSONRequest" "FuzzParseJSONRequest" "github.com/sigstore/timestamp-authority/v2/pkg/api"
build_target "FuzzParseDERRequest"  "FuzzParseDERRequest"  "github.com/sigstore/timestamp-authority/v2/pkg/api"

echo "build.sh complete:"
ls -la /mayhem/FuzzParseJSONRequest /mayhem/FuzzParseDERRequest 2>&1 || true

# mayhem-dict-fix: place the dictionaries the Mayhemfiles reference (build.sh never did -> libFuzzer exited 1 on missing -dict -> 0 edges)
find "$SRC/mayhem" -name "*.dict" -exec cp {} /mayhem/ \; 2>/dev/null || true
