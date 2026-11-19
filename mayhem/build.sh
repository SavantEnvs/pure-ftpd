#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# pure-ftpd ships no generated configure: autogen.sh (aclocal/autoheader/automake/autoconf, all in
# the base image) creates it in the source tree. Its outputs are gitignored by upstream, so a
# `git clean -ffdX`-ed tree regenerates them here.
[ -x configure ] && [ -f Makefile.in ] && [ -f src/Makefile.in ] || sh autogen.sh

# Shared feature set: everything the server can be built with that needs no external server or
# library (no TLS/LDAP/MySQL/PGSQL/PAM), in non-root mode so it runs as `mayhem`/`sandbox`.
CONFIGURE_ARGS=(--with-everything --with-nonroot --without-capabilities --without-pam
                --with-virtualchroot)

B="$SRC/mayhem/build"
OUT="$SRC/mayhem/out"
mkdir -p "$B/fuzz" "$B/test" "$OUT"

# 1) Sanitized build of the whole project (out of tree, mayhem/build/fuzz). configure runs with
#    plain flags so its feature probes aren't tripped by halting UBSan; the sanitizer + DWARF-3 flags
#    go to make, so every project object is instrumented. -fsanitize=fuzzer-no-link adds SanCov to
#    the project code the libFuzzer target links.
# UBSan relaxation (only this one check; ASan and the rest of UBSan stay halting): shift-base.
# PureDB decodes every big-endian u32 as `p[0] << 24 | ...` with p[] unsigned char promoted to int
# (puredb/src/puredb_read.c read_be_long and its callers), so any offset/length byte >= 0x80 is a
# shift into the sign bit; it fires on most inputs and would mask every real PureDB bug behind it.
# shift-exponent (an oversized shift count, e.g. the CIDR-width bug class) stays on.
UBSAN_RELAX="-fno-sanitize=shift-base"
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $UBSAN_RELAX"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c "$SRC/mayhem/harnesses/inetd_shim.c" -o "$B/inetd_shim.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c "$SRC/mayhem/harnesses/env_mocks.c" -o "$B/env_mocks.o"
FUZZ_LDFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $B/lsan_off.o"
( cd "$B/fuzz" && "$SRC/configure" CC="$CC" CFLAGS="-O1" "${CONFIGURE_ARGS[@]}" >/dev/null &&
  make -j"$MAYHEM_JOBS" CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$FUZZ_LDFLAGS" >/dev/null )
# pure-ftpd relinked from the same objects + the inetd shim (fd 0 = a socket carrying the input)
# + env_mocks.o (no login-failure sleeps, no RLIMIT_DATA under ASan; see the file).
rm -f "$B/fuzz/src/pure-ftpd"
make -C "$B/fuzz/src" pure-ftpd CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$FUZZ_LDFLAGS $B/inetd_shim.o $B/env_mocks.o" >/dev/null
cp "$B/fuzz/src/pure-ftpd" "$OUT/pure-ftpd-inetd"
cp "$B/fuzz/src/pure-pw" "$OUT/pure-pw"

# 2) libFuzzer target over the PureDB reader API + its standalone reproducer.
PDB_INC=(-I"$B/fuzz" -I"$SRC/puredb/src")
$CC $FUZZ_CFLAGS "${PDB_INC[@]}" -c "$SRC/puredb/src/puredb_read.c" -o "$B/puredb_read.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $UBSAN_RELAX -O1 "${PDB_INC[@]}" -c "$SRC/mayhem/harnesses/fuzz_puredb_read.c" -o "$B/fuzz_puredb_read.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz_puredb_read.o" "$B/puredb_read.o" \
    "$B/lsan_off.o" -o "$OUT/fuzz_puredb_read"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/fuzz_puredb_read.o" "$B/puredb_read.o" \
    "$B/lsan_off.o" -o "$OUT/fuzz_puredb_read-standalone"

# 3) Test/oracle build with the project's NORMAL flags (mayhem/build/test): upstream's PureDB
#    regression program, pure-pw, and pure-ftpd + the same inetd shim for a scripted session.
( cd "$B/test" && "$SRC/configure" CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    "${CONFIGURE_ARGS[@]}" >/dev/null && make -j"$MAYHEM_JOBS" >/dev/null )
$CC -O2 $COVERAGE_FLAGS -c "$SRC/mayhem/harnesses/inetd_shim.c" -o "$B/test/inetd_shim.o"
rm -f "$B/test/src/pure-ftpd"
make -C "$B/test/src" pure-ftpd LDFLAGS="$COVERAGE_FLAGS $B/test/inetd_shim.o" >/dev/null
cp "$B/test/src/pure-ftpd" "$B/test/pure-ftpd-inetd"

ls -l "$OUT"
