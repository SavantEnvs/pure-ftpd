#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

# Known-answer tests over the NORMAL-flags build in mayhem/build/test (made by build.sh). Each test
# asserts the program's output, so a neutered (exit 0) binary fails every one of them.
T="$SRC/mayhem/build/test"
for b in "$T/puredb/src/regression" "$T/src/pure-pw" "$T/pure-ftpd-inetd"; do
  [ -x "$b" ] || { echo "missing $b — run mayhem/build.sh first" >&2; emit_ctrf "pure-ftpd-kat" 0 1 0; exit 1; }
done
W=$(mktemp -d "${TMPDIR:-/tmp}/pure-ftpd-test.XXXXXX")
trap 'rm -rf "$W"' EXIT
passed=0 failed=0
check() {   # check <name> <command…>: the command is a test returning 0 on pass
  local name="$1"; shift
  if "$@"; then echo "PASS $name"; passed=$((passed+1)); else echo "FAIL $name"; failed=$((failed+1)); fi
}
has() { grep -qF -- "$2" "$1" || { echo "  expected [$2] in $1:"; sed 's/^/    | /' "$1"; return 1; }; }
lacks() { ! grep -qF -- "$2" "$1" || { echo "  unexpected [$2] in $1"; return 1; }; }

# 1) Upstream's PureDB regression program: writes ~400k records, reads every one back, probes misses.
t_regression() {
  ( cd "$W" && export FTPD_SHIM_ECHO=1 && "$T/puredb/src/regression" ) > "$W/regression.out" 2>&1 &&
  has "$W/regression.out" "records have been written" &&
  [ "$(grep -c 'Success!' "$W/regression.out")" -eq 2 ]
}
check puredb-regression t_regression

# 2) pure-pw: add a user, show it back, build the .pdb.
t_purepw() {
  printf 'secret\nsecret\n' | "$T/src/pure-pw" useradd joe -u 4242 -g 4343 -d "$W/home/joe" \
      -c 'Joe Tester' -n 10 -f "$W/passwd" > "$W/useradd.out" 2>&1 &&
  has "$W/passwd" "joe:" &&
  "$T/src/pure-pw" show joe -f "$W/passwd" > "$W/show.out" 2>&1 &&
  has "$W/show.out" "Login              : joe" &&
  has "$W/show.out" "UID                : 4242" &&
  has "$W/show.out" "GID                : 4343" &&
  has "$W/show.out" "Directory          : $W/home/joe/./" &&
  has "$W/show.out" "Full name          : Joe Tester" &&
  has "$W/show.out" "Max files          : 10" &&
  "$T/src/pure-pw" mkdb "$W/users.pdb" -f "$W/passwd" > "$W/mkdb.out" 2>&1 &&
  [ -s "$W/users.pdb" ] && head -c 6 "$W/users.pdb" | grep -q '^PDB2'
}
check pure-pw t_purepw
mkdir -p "$W/home/joe" "$W/anon"
printf 'hello\n' > "$W/anon/hello.txt"

# 3) An anonymous FTP session (pure-ftpd in inetd mode over the shim), checking each reply.
t_anon() {
  ( cd "$W" && export FTPD_SHIM_ECHO=1 && FTP_ANON_DIR="$W/anon" \
    FTPD_SHIM_SCRIPT='USER anonymous\r\nPASS x\r\nPWD\r\nTYPE I\r\nSIZE hello.txt\r\nSIZE nope\r\nSYST\r\nQUIT\r\n' \
    "$T/pure-ftpd-inetd" -H -e ) 2>&1 | cat > "$W/anon.out" ;
  sed 's/^/    > /' "$W/anon.out" | head -40
  has "$W/anon.out" "220" && has "$W/anon.out" "230 " && has "$W/anon.out" '257 "/" is your current location' &&
  has "$W/anon.out" "213 6" && has "$W/anon.out" "550 " && has "$W/anon.out" "215 UNIX Type: L8" &&
  has "$W/anon.out" "221"
}
check ftp-anonymous-session t_anon

# 4) A PureDB virtual-user login against the .pdb built in test 2 (right and wrong password).
t_puredb_login() {
  ( cd "$W" && export FTPD_SHIM_ECHO=1 && FTPD_SHIM_SCRIPT='USER joe\r\nPASS secret\r\nPWD\r\nQUIT\r\n' \
    "$T/pure-ftpd-inetd" -H -E -l "puredb:$W/users.pdb" ) 2>&1 | cat > "$W/login.out" ;
  ( cd "$W" && export FTPD_SHIM_ECHO=1 && FTPD_SHIM_SCRIPT='USER joe\r\nPASS wrong\r\nQUIT\r\n' \
    "$T/pure-ftpd-inetd" -H -E -l "puredb:$W/users.pdb" ) 2>&1 | cat > "$W/badlogin.out" ;
  has "$W/login.out" "230 " && has "$W/login.out" '257 "/" is your current location' &&
  has "$W/badlogin.out" "530 " && lacks "$W/badlogin.out" "230 "
}
check ftp-puredb-login t_puredb_login

# 4b) A logged-in user's write/modify commands (what the ftp-user-session target fuzzes): the replies
#     AND the resulting files on disk (mode, mtime, renames, deletions) are checked.
t_user_writes() {
  local H="$W/home/joe"
  ( cd "$W" && export FTPD_SHIM_ECHO=1 && FTPD_SHIM_SCRIPT='USER joe\r\nPASS secret\r\nMKD d1\r\nCWD d1\r\nPWD\r\nCDUP\r\nRNFR d1\r\nRNTO d2\r\nMKD gone\r\nRMD gone\r\nSTOR f.txt\r\nSITE CHMOD 640 f.txt\r\nMFMT 20200102030405 f.txt\r\nRNFR f.txt\r\nRNTO d2/g.txt\r\nSITE UTIME d2 20210304050607 20210304050607 20210304050607 UTC\r\nSTOR del.txt\r\nDELE del.txt\r\nQUIT\r\n' \
    "$T/pure-ftpd-inetd" -H -E -l "puredb:$W/users.pdb" ) 2>&1 | cat > "$W/writes.out" ;
  has "$W/writes.out" '257-"d1" : The directory was successfully created' &&
  has "$W/writes.out" '257 "/d1" is your current location' &&
  has "$W/writes.out" "350 RNFR accepted" && has "$W/writes.out" "250 File successfully renamed or moved" &&
  has "$W/writes.out" "250 The directory was successfully removed" &&
  has "$W/writes.out" "200 Permissions changed on f.txt" && has "$W/writes.out" "213 UTIME OK" &&
  has "$W/writes.out" "250 Deleted del.txt" &&
  [ -d "$H/d2" ] && [ ! -e "$H/d1" ] && [ ! -e "$H/gone" ] && [ ! -e "$H/del.txt" ] &&
  [ -f "$H/d2/g.txt" ] && [ ! -e "$H/f.txt" ] &&
  [ "$(stat -c %a "$H/d2/g.txt")" = 640 ] && [ "$(stat -c %Y "$H/d2/g.txt")" = 1577934245 ] &&
  [ "$(stat -c %Y "$H/d2")" = 1614834367 ]
}
check ftp-user-writes t_user_writes

# 5) The configuration-file parser: NoAnonymous in a config file must refuse the anonymous login.
t_config() {
  printf 'NoAnonymous yes\nDontResolve yes\nUnixAuthentication no\n' > "$W/ftpd.conf"
  ( cd "$W" && export FTPD_SHIM_ECHO=1 && FTP_ANON_DIR="$W/anon" FTPD_SHIM_SCRIPT='USER anonymous\r\nPASS x\r\nQUIT\r\n' \
    "$T/pure-ftpd-inetd" "$W/ftpd.conf" ) 2>&1 | cat > "$W/conf.out" ;
  has "$W/conf.out" "220" && has "$W/conf.out" "530 " && lacks "$W/conf.out" "230 "
}
check ftpd-config t_config

emit_ctrf "pure-ftpd-kat" "$passed" "$failed" 0
