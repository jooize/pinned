#!/usr/bin/env bash
# Fixture harness for `pinned` -- drives a STUBBED COPY of the real script.
#
# Run it with the Claude Code sandbox OFF (like the hardening harnesses):
#     bash tests/harness.bash
# The git fixture in S8 calls `git init` in a scratch dir, which the sandbox
# denies; every git call here is `git -C <absolute path>` and S8 asserts the
# fixture's own toplevel first, so a denied init fails loudly instead of
# silently operating on a PARENT repository.
#
# WHY A STUB: pinned is a root tool. The copy under $TMPDIR is seded at
# EXACTLY the root/ownership seams, and nothing else:
#   1. the self-elevation `if [ "$EUID" -ne 0 ]` gates -> `if false`
#      (no exec sudo; the ceremony body runs in this process)
#   2. require_root's EUID/SUDO_USER checks -> inv="$(id -un)"
#   3. the owner allowlist `root:*)` -> `root:*|<user>:*)` in
#      verify_root_owned_path and verify_record_file (the MODE half of both
#      checks stays intact and is exercised: 0750 ancestry, non-group-writable
#      records)
#   4. `install -o root -g ...` / `chown root:...` -> plain install / no-op
#   5. `read -r answer </dev/tty` -> read from stdin, so ceremonies are
#      driven by $ANS (each diff pager sits behind an Enter-gate, so a
#      gated review consumes one extra line -- blank -- before its y/N)
#   6. log_action's `logger -t pinned` -> no-op, so fixture ceremonies never
#      land in the machine's real approval history
# A SECOND stub (the preview one, S8h) keeps the elevation gate live and
# replaces sudo itself; its four extra seams are documented where it is built.
# Every anchor is counted in the source BEFORE the sed (see need()), so a
# drifting script aborts the harness loudly instead of silently testing a
# no-op stub. INSTALL_TARGET is an honest environment override the script
# already supports; PINNED_ROOT and PINNED_MACHINE_POLICY are compile-time
# constants in the real script, so they are anchored and rewritten by the sed
# like any other. Nothing here touches /var/db/pinned, /etc, or any live
# system state.
#
# canon_path / encode / decode / write_slot_state are unit-driven through a
# PROBE: the stub truncated before its first action (a pure function library)
# is sourced, then one function is called by name.
#
# KNOWN COVERAGE GAPS (deliberate):
#   - no real sudo, so the sudoers digest pin and `setup` are untested here,
#     as is any deploy that actually rebuilds. The one piece of setup that is
#     covered is its interpreter guard (S17), reached through the PROBE as a
#     function plus a source-level check of where do_setup calls it
#   - the self-elevation preview is covered for `upgrade` only (S8h, via the
#     preview stub): the no-op exit, the Enter-gate and their refusals. The
#     review/add previews -- including the preview's mirrored copies of
#     review --step's refusals -- stay untested (S8e covers the root-side
#     originals, which are the authoritative half)
#   - signed-tag approval / `signer` / `sign` need an SSH agent and keys
#   - the group-read tier (0750 root:_<user>-pinned) cannot be built without
#     root: the stub always takes ensure_tree's no-group 0700 branch
#   - `add` clones as the harness user directly: the real `sudo -u <invoker>`
#     drop, and the clone tree's root:_pinned-clones 2775 ownership, need
#     root -- the stub always takes the no-group branch there too, so what
#     S15 covers is the clone's scrubbed environment, its provenance rules
#     and everything downstream of it, never the privilege drop itself
#   - blake2b/blake3 algorithms are not exercised (sha256 only)
#   - `show` and `status <repo>` dirty-tree warnings: only status's
#     approved/never-approved verdicts are covered
#
# S8's first case is a REGRESSION test: a first-ever repo approval (no slot
# dir yet) must succeed. This harness caught it refusing on delivery day --
# the same not-yet-created-slot ancestry defect review --file had -- and
# the fix landed with the harness. Details at the S8 comment.

set -euo pipefail
export LC_ALL=C   # byte semantics for the encode/decode round-trips

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(dirname "$HERE")/pinned"
PASS=0 FAIL=0

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); say "  ok: $1"; }
fail() { FAIL=$((FAIL + 1)); say "  FAIL: $1"; }

assert_exit() { # got want label
  if [ "$1" = "$2" ]; then ok "$3"; else fail "$3 (exit $1, want $2)"; fi
}
assert_eq() { # got want label
  if [ "$1" = "$2" ]; then ok "$3"; else fail "$3 (got '$1', want '$2')"; fi
}
assert_contains() { # file needle label
  if grep -qF -e "$2" "$1"; then ok "$3"; else fail "$3 (no '$2' in output)"; fi
}
assert_missing() { # file needle label
  if grep -qF -e "$2" "$1"; then fail "$3 (unexpected '$2' in output)"; else ok "$3"; fi
}
assert_before() { # file first-needle second-needle label -- ORDER on the page
  # Some displays are only correct in one order (orientation, then the thing
  # under decision, then the gate), and every needle being present says
  # nothing about that. Both must appear, first strictly above second.
  local a b
  a="$(grep -nF -m1 -e "$2" "$1" | cut -d: -f1)"
  b="$(grep -nF -m1 -e "$3" "$1" | cut -d: -f1)"
  if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then
    ok "$4"
  else
    fail "$4 (line of '$2' = ${a:-none}, of '$3' = ${b:-none})"
  fi
}
assert_row() { # file label path desc -- ONE output line carries both
  # The upgrade plan is one row per input: label column, then the path. The
  # pairing is what the assertions are about ("this path is highlighted for
  # approval"), and the column width moves with the labels a plan happens to
  # hold, so the two needles are matched on the same line, not on the page.
  if grep -F -e "$3" "$1" | grep -qF -e "$2"; then ok "$4"; else fail "$4 (no '$2' row for $3)"; fi
}
assert_no_row() { # file label path desc
  if grep -F -e "$3" "$1" | grep -qF -e "$2"; then fail "$4 (unexpected '$2' row for $3)"; else ok "$4"; fi
}
assert_file() { # path label
  if [ -f "$1" ]; then ok "$2"; else fail "$2 (no such file: $1)"; fi
}
assert_absent() { # path label
  if [ -e "$1" ]; then fail "$2 (still present: $1)"; else ok "$2"; fi
}

[ -f "$SRC" ] || { say "no pinned script at $SRC"; exit 2; }
command -v git >/dev/null 2>&1 || { say "git is required for S8"; exit 2; }

# --- stub construction ------------------------------------------------------

FIX="$(mktemp -d "${TMPDIR:-/tmp}/pinned-harness.XXXXXX")"
FIX="$(cd "$FIX" && pwd -P)"
STUB="$FIX/pinned-stub"
LIB="$FIX/pinned-lib.bash"
PROBE="$FIX/probe"
OUT="$FIX/out"
ERRF="$FIX/err"
SUB="$FIX/subjects"
USERNAME="$(id -un)"
ANS=""
RC=0
POUT=""
# The preview stub's two env seams (see run_preview); empty = a tty,
# unprivileged.
NOTTY=""
TESTROOT=""

# Fixture paths for the two constants the sed below bakes into the stub. They
# are plain shell variables here -- the harness uses them to build and inspect
# fixture state; exporting them would do nothing, since the stub no longer
# reads the environment for either.
PINNED_ROOT="$FIX/pinroot"
# The shared clone tree `add` provisions for url arguments (S15).
PINNED_CLONES="$FIX/pinclones"
export INSTALL_TARGET="$FIX/no-such-install"
# The OPTIONAL machine tier of the ignorable policy, pointed at the fixture
# instead of /etc/pinned so the harness never reads (or needs) machine state.
# Absent by default: most sections want "no machine constraint".
PINNED_MACHINE_POLICY="$FIX/etc-pinned/ignorable.json"
POLICY_USER="$PINNED_ROOT/$USERNAME/policy/ignorable.json"

need() { # regex count label -- the sed anchors must still exist, exactly
  local n
  n="$(grep -c -e "$1" "$SRC" || true)"
  [ "$n" = "$2" ] && return 0
  say "STUB ANCHOR DRIFT: $3"
  say "  pattern /$1/ matched $n line(s) in $SRC, want $2"
  say "  the harness cannot stub a script it no longer recognizes; fix the anchor"
  exit 2
}

need 'if \[ "\$EUID" -ne 0 \]; then'                        2 'self-elevation gates'
need '^  \[ "\$EUID" -eq 0 \] ||'                           1 'require_root EUID check'
need '^  inv="\${SUDO_USER:-}"$'                            1 'require_root SUDO_USER read'
need '^  \[ -n "\$inv" \] ||'                               1 'require_root sudo check'
need '^    root:\*) ;;$'                                    2 'owner allowlists'
need '^PINNED_ROOT=/var/db/pinned$'                         1 'pin-root constant'
need '^PINNED_CLONES=/var/db/pinned-clones$'                1 'clone-tree constant'
need '^PINNED_MACHINE_POLICY=/etc/pinned/ignorable.json$'   1 'machine-policy constant'
need '^  install -d -m 755 -o root -g wheel "\$PINNED_ROOT"$'  1 'pin-root install'
need '^  install -d -m 755 -o root -g wheel "\$PINNED_CLONES"$' 1 'clone-tree install'
need '^    install -d -m 2775 -o root -g "\$PINNED_CLONES_GROUP" "\$CLONE_DIR"$' 1 'clone-dir install (group)'
need '^    install -d -m 755 -o "\$inv" "\$CLONE_DIR"$'     1 'clone-dir install (no group)'
need '^  sudo -u "\$inv" env -i PATH="\$PATH" \\$'          1 'clone drops to the invoker'
need '-o root -g "\$TREE_GRP" '                             4 'slot-tree installs'
need '^  chown -R "root:\$TREE_GRP"'                        1 'tree chown sweep'
need 'chown "root:\$TREE_GRP"'                              5 'record chowns'
need '^  logger -t pinned '                                 1 'audit-log call'
need '</dev/tty'                                            19 'ceremony tty reads'
need '^# ---- setup ---'                                    1 'library cut marker'
need '^#!/bin/bash$'                                        1 'pinned shebang'
# The preview stub's own anchors (see its construction below).
need 'exec sudo -- "\$elev" "\$action" "\$@"'               2 'self-elevation exec sites'
need 'verify_ancestry "\$elev" || exit 1'                   2 'elevation-target ancestry walks'
need '^  verify_ancestry "\$INSTALL_TARGET" || exit 1$'     1 'install-target ancestry walk'
need 'if \[ ! -t 0 \]; then'                                2 'no-tty refusals'
need '^  if \[ "\$EUID" -eq 0 \]; then SUDO_ARGV=(); sudo_disp=""; fi$' 1 "deploy's sudo drop"

# ...one of them being line 1. The script pins /bin/bash because sudo hands
# root the caller's PATH (see the comment above its PATH export), but a
# FIXTURE copy must run wherever the harness runs -- NixOS has no /bin/bash.
# So the stub is pointed at whichever bash is executing this file, which also
# makes the compatibility floor a deliberate choice rather than an accident:
#     bash tests/harness.bash        the bash on your PATH
#     /bin/bash tests/harness.bash   the 3.2 floor the script is written to
HARNESS_BASH="${BASH:-bash}"

# ---------------------------------------------------------------------------
say "S0: the bash 3.2 parse floor"
# ---------------------------------------------------------------------------
# Choosing the harness interpreter proves nothing on its own: run under a 5.x
# on PATH, every section below passes while the script the shebang names
# refuses to start. `bash -n` parses the SOURCE under that interpreter without
# running a line of it, which is exactly what catches a 4.x-ism (an
# associative array, [[ -v ]], mapfile) landing in a script whose floor is
# macOS's sealed /bin/bash. Where there is no /bin/bash the floor cannot be
# measured, so the check says so rather than passing quietly.
if [ -x /bin/bash ]; then
  if /bin/bash -n "$SRC" 2>"$ERRF"; then
    ok "the script parses under /bin/bash (the 3.2 floor)"
  else
    fail "the script parses under /bin/bash (the 3.2 floor)"
    sed 's/^/      /' "$ERRF"
  fi
else
  say "S0: SKIPPED (no /bin/bash -- the 3.2 floor is unmeasurable here)"
fi

# The seams both stubs share. Held in an array because a SECOND stub (the
# preview one built further down) needs exactly these and a different
# elevation seam -- two copies of this list would drift.
STUB_SED=(
    -e "1s#^\#!/bin/bash\$#\#!$HARNESS_BASH#"
    -e "s#^PINNED_ROOT=/var/db/pinned\$#PINNED_ROOT='$PINNED_ROOT'#"
    -e "s#^PINNED_CLONES=/var/db/pinned-clones\$#PINNED_CLONES='$PINNED_CLONES'#"
    -e "s#^PINNED_MACHINE_POLICY=/etc/pinned/ignorable.json\$#PINNED_MACHINE_POLICY='$PINNED_MACHINE_POLICY'#"
    -e 's/^  \[ "\$EUID" -eq 0 \] ||.*/  :/'
    -e 's/^  inv="\${SUDO_USER:-}"$/  inv="$(id -un)"/'
    -e 's/^  \[ -n "\$inv" \] ||.*/  :/'
    -e "s/^    root:\\*) ;;\$/    root:*|${USERNAME}:*) ;;/"
    -e 's/^  install -d -m 755 -o root -g wheel "\$PINNED_ROOT"$/  install -d -m 755 "$PINNED_ROOT"/'
    -e 's/^  install -d -m 755 -o root -g wheel "\$PINNED_CLONES"$/  install -d -m 755 "$PINNED_CLONES"/'
    -e 's/^\( *\)install -d -m 2775 -o root -g "\$PINNED_CLONES_GROUP" /\1install -d -m 2775 /'
    -e 's/^\( *\)install -d -m 755 -o "\$inv" /\1install -d -m 755 /'
    -e 's/^  sudo -u "\$inv" env -i /  env -i /'
    -e 's/-o root -g "\$TREE_GRP" //g'
    -e 's/^\( *\)chown -R "root:\$TREE_GRP".*/\1:/'
    -e 's/^\( *\)chown "root:\$TREE_GRP".*/\1:/'
    -e 's/^  logger -t pinned .*/  :/'
    -e 's#</dev/tty##g'
)
sed "${STUB_SED[@]}" \
    -e 's/if \[ "\$EUID" -ne 0 \]; then/if false; then/' \
    "$SRC" > "$STUB"
chmod 755 "$STUB"

# Post-conditions: the seds actually landed (a silently-unapplied sed would
# turn every ceremony test into a hang or a sudo prompt).
if grep -q '^PINNED_ROOT=/var/db/pinned$' "$STUB"; then
  say "STUB SED FAILED: the real pin root survives"; exit 2
fi
if grep -q '^PINNED_CLONES=/var/db/pinned-clones$' "$STUB"; then
  say "STUB SED FAILED: the real clone tree survives"; exit 2
fi
if grep -q '^PINNED_MACHINE_POLICY=/etc/pinned/ignorable.json$' "$STUB"; then
  say "STUB SED FAILED: the real machine policy path survives"; exit 2
fi
if grep -q '^  sudo -u "\$inv" env -i ' "$STUB"; then
  say "STUB SED FAILED: the clone still drops to the invoker via sudo"; exit 2
fi
if grep -q '</dev/tty' "$STUB"; then say "STUB SED FAILED: /dev/tty survives"; exit 2; fi
if [ "$(grep -c 'if false; then' "$STUB")" != 2 ]; then say "STUB SED FAILED: elevation gates"; exit 2; fi
if grep -q '^  logger -t pinned ' "$STUB"; then say "STUB SED FAILED: logger survives"; exit 2; fi
if [ "$(head -n1 "$STUB")" != "#!$HARNESS_BASH" ]; then
  say "STUB SED FAILED: the stub shebang still reads $(head -n1 "$STUB")"; exit 2
fi

# --- the preview stub -------------------------------------------------------
# The main stub's `if false` elevation seam means the ceremony body runs and
# the PRE-SUDO half never does. This second copy covers that half for
# upgrade: the elevation gate stays LIVE (this process is not root, so the
# gate is taken for real) and only sudo itself is replaced -- `exec sudo ...`
# becomes `exit 97`, a status nothing else in the script produces, so
# "reached the elevation" is an assertion and no root command can run.
#
# Seams beyond the shared list:
#   7. exec sudo -> exit 97, at both call sites
#   8. verify_ancestry on the elevation target -> no-op. INSTALL_TARGET is
#      this stub, under $TMPDIR, whose ancestry is nobody's root-owned tree;
#      the owner/mode check on the target ITSELF stays live (allowlist seam)
#   9. the two no-tty refusals -> $PINNED_TEST_NOTTY, so both branches of a
#      gate are drivable from one stub
#  10. deploy's EUID==0 sudo drop -> $PINNED_TEST_ROOT: the only way to see
#      the root-context command display from an unprivileged harness
PREVIEW="$FIX/pinned-preview"
sed "${STUB_SED[@]}" \
    -e 's/exec sudo -- "\$elev" "\$action" "\$@"/exit 97/' \
    -e 's/verify_ancestry "\$elev" || exit 1/:/' \
    -e 's/^  verify_ancestry "\$INSTALL_TARGET" || exit 1$/  :/' \
    -e 's/if \[ ! -t 0 \]; then/if [ -n "${PINNED_TEST_NOTTY:-}" ]; then/' \
    -e 's/^  if \[ "\$EUID" -eq 0 \]; then SUDO_ARGV=(); sudo_disp=""; fi$/  if [ -n "${PINNED_TEST_ROOT:-}" ]; then SUDO_ARGV=(); sudo_disp=""; fi/' \
    "$SRC" > "$PREVIEW"
chmod 755 "$PREVIEW"

if grep -q 'exec sudo -- ' "$PREVIEW"; then
  say "PREVIEW SED FAILED: an exec sudo survives"; exit 2
fi
if [ "$(grep -c '^ *exit 97$' "$PREVIEW")" != 2 ]; then
  say "PREVIEW SED FAILED: sudo markers"; exit 2
fi
if grep -q 'if false; then' "$PREVIEW"; then
  say "PREVIEW SED FAILED: the elevation gate was stubbed out"; exit 2
fi
if [ "$(grep -c 'PINNED_TEST_NOTTY' "$PREVIEW")" != 2 ]; then
  say "PREVIEW SED FAILED: no-tty seams"; exit 2
fi
if ! grep -q 'PINNED_TEST_ROOT' "$PREVIEW"; then
  say "PREVIEW SED FAILED: root seam"; exit 2
fi

# The pure-function library: everything above the first action.
sed '/^# ---- setup ---/,$d' "$STUB" > "$LIB"

cat > "$PROBE" <<EOF
#!$HARNESS_BASH
# Call one internal pinned function by name. Args are captured BEFORE the
# source so the library's own positional-parameter handling cannot touch them.
set -euo pipefail
fn="\$1"; shift
args=("\$@")
# shellcheck disable=SC1090
. "$LIB" probe
"\$fn" \${args[@]+"\${args[@]}"}
EOF
chmod 755 "$PROBE"

mkdir -p "$SUB"

# --- drivers ----------------------------------------------------------------

run_pinned() { # verb args... -- stdin comes from \$ANS, output lands in \$OUT
  printf '%s' "$ANS" > "$FIX/stdin"
  RC=0
  "$STUB" "$@" <"$FIX/stdin" >"$OUT" 2>&1 || RC=$?
}
run_pinned_split() { # verb args... -- like run_pinned, but stderr stays in \$ERRF
  # `cat` is the one verb with a stdout CONTRACT ("nothing on stdout in any
  # failure case"), which a merged stream cannot test.
  printf '%s' "$ANS" > "$FIX/stdin"
  RC=0
  "$STUB" "$@" <"$FIX/stdin" >"$OUT" 2>"$ERRF" || RC=$?
}
run_preview() { # verb args... -- run_pinned against the PREVIEW stub
  # INSTALL_TARGET is this very stub, so `elev == INSTALL_TARGET` holds and
  # the pre-sudo display block is reached. $NOTTY / $TESTROOT drive the two
  # env seams; both default to empty, i.e. "a tty, unprivileged".
  printf '%s' "$ANS" > "$FIX/stdin"
  RC=0
  INSTALL_TARGET="$PREVIEW" PINNED_TEST_NOTTY="$NOTTY" PINNED_TEST_ROOT="$TESTROOT" \
    "$PREVIEW" "$@" <"$FIX/stdin" >"$OUT" 2>&1 || RC=$?
}
run_probe() { # fn args... -- stdout in \$POUT, stderr in \$ERRF
  RC=0
  POUT="$("$PROBE" "$@" 2>"$ERRF")" || RC=$?
}
run_probe_in() { # dir fn args...
  local d="$1"; shift
  RC=0
  POUT="$(cd "$d" && "$PROBE" "$@" 2>"$ERRF")" || RC=$?
}

slot_of()   { "$PROBE" slot_dir_for "$USERNAME" "$1"; }
digest_of() { shasum -a 256 "$1" | awk '{print $1}'; }

seed_state() { # path state-file content
  local d
  d="$(slot_of "$1")"
  mkdir -p "$d"
  printf '%s\n' "$3" > "$d/$2"
  chmod 640 "$d/$2"
}
seed_pin()       { seed_state "$1" pin.sha256 "$2  $1"; }
seed_tombstone() { seed_state "$1" tombstone "1970-01-01T00:00:00Z retired by $USERNAME"; }

slot_file_of() { # subject-path slot-file-name -> absolute path inside the slot
  printf '%s/%s\n' "$(slot_of "$1")" "$2"
}

seed_policy_user() { # policy-json -- the user tier, as a root ceremony would write it
  mkdir -p "$(dirname "$POLICY_USER")"
  printf '%s\n' "$1" > "$POLICY_USER"
  chmod 640 "$POLICY_USER"
}
seed_policy_machine() { # policy-json -- the optional machine tier
  mkdir -p "$(dirname "$PINNED_MACHINE_POLICY")"
  printf '%s\n' "$1" > "$PINNED_MACHINE_POLICY"
  chmod 644 "$PINNED_MACHINE_POLICY"
}

count_state() { # slot-dir -> how many of rev.* / pin.* / tombstone exist
  local d="$1" f n=0
  for f in "$d"/rev.* "$d"/pin.* "$d"/tombstone; do
    if [ -e "$f" ]; then n=$((n + 1)); fi
  done
  printf '%s\n' "$n"
}

# ---------------------------------------------------------------------------
say "S1: canon_path"
# ---------------------------------------------------------------------------
printf 'real\n' > "$SUB/real.txt"
ln -s real.txt "$SUB/link.txt"
mkdir -p "$SUB/realdir"
ln -s realdir "$SUB/linkdir"

run_probe canon_path "$SUB/link.txt"
assert_exit "$RC" 0 "existing symlink: exit 0"
assert_eq "$POUT" "$SUB/real.txt" "existing symlink resolves to its target"

run_probe canon_path "$SUB/absent.txt"
assert_exit "$RC" 0 "absent file with existing parent: exit 0"
assert_eq "$POUT" "$SUB/absent.txt" "absent file keeps its literal tail"

run_probe canon_path "$SUB/gone/absent.txt"
assert_exit "$RC" 0 "absent file with MISSING parent: exit 0 (regression)"
assert_eq "$POUT" "$SUB/gone/absent.txt" "missing parent resolves via nearest ancestor"

run_probe canon_path "$SUB/a/b/c/d/e"
assert_exit "$RC" 0 "five missing components: exit 0"
assert_eq "$POUT" "$SUB/a/b/c/d/e" "five missing components resolve literally"

run_probe canon_path "$SUB/linkdir/absent"
assert_exit "$RC" 0 "symlinked existing ancestor: exit 0"
assert_eq "$POUT" "$SUB/realdir/absent" "symlinked ancestor resolves, tail stays literal"

run_probe canon_path "$SUB/gone/../x"
assert_exit "$RC" 1 "'..' below a missing directory refuses"
assert_contains "$ERRF" ".. below a missing directory" "refusal names the reason"

run_probe_in "$SUB" canon_path real.txt
assert_exit "$RC" 0 "relative existing path: exit 0"
assert_eq "$POUT" "$SUB/real.txt" "relative existing path becomes absolute"

run_probe_in "$SUB" canon_path nowhere/rel.txt
assert_exit "$RC" 0 "relative missing path: exit 0"
assert_eq "$POUT" "$SUB/nowhere/rel.txt" "relative missing path becomes absolute"

# ---------------------------------------------------------------------------
say "S2: encode / decode"
# ---------------------------------------------------------------------------
rt() { # path label -- round-trip identity plus the slot-name charset
  local enc dec
  enc="$("$PROBE" encode "$1")"
  dec="$("$PROBE" decode "$enc")"
  assert_eq "$dec" "$1" "round-trip: $2"
  case "$enc" in
    *[!A-Za-z0-9._%-]*) fail "charset: $2 (encoded '$enc' has an out-of-set byte)" ;;
    *)                  ok   "charset: $2" ;;
  esac
}

NFC=$'/tmp/caf\xc3\xa9/settings.json'        # e-acute as one code point
NFD=$'/tmp/cafe\xcc\x81/settings.json'       # e + combining acute

rt "/Users/jooize/Projects/pinned"                        "plain path"
rt "/Library/Application Support/Claude/managed.json"     "spaces"
rt "/tmp/proj[1]/*.conf?"                                 "glob metacharacters"
rt '/tmp/$(id -un)/`whoami`/x'                            "command substitution chars"
rt "/tmp/it's \"quoted\"/x"                               "quotes"
rt "$NFC"                                                 "UTF-8 NFC"
rt "$NFD"                                                 "UTF-8 NFD"

assert_eq "$("$PROBE" encode "/Users/jooize/Projects/pinned")" \
          "%2FUsers%2Fjooize%2FProjects%2Fpinned" \
          "backward compat: pre-existing slot name is byte-identical"
assert_eq "$("$PROBE" encode "$NFC")" "%2Ftmp%2Fcaf%C3%A9%2Fsettings.json" \
          "NFC encodes its own bytes"
if [ "$("$PROBE" encode "$NFC")" = "$("$PROBE" encode "$NFD")" ]; then
  fail "NFC and NFD must encode to DISTINCT slot names (no normalization)"
else
  ok "NFC and NFD encode to distinct slot names (no normalization)"
fi

# ---------------------------------------------------------------------------
say "S3: verify exit contract"
# ---------------------------------------------------------------------------
mkdir -p "$SUB/v"
printf 'pinned content\n' > "$SUB/v/match.txt"
seed_pin "$SUB/v/match.txt" "$(digest_of "$SUB/v/match.txt")"
run_pinned verify "$SUB/v/match.txt"
assert_exit "$RC" 0 "pin matches -> 0"
assert_contains "$OUT" "verified" "success names the verdict"

printf 'emitted bytes\n' > "$SUB/v/emit.txt"
seed_pin "$SUB/v/emit.txt" "$(digest_of "$SUB/v/emit.txt")"
run_pinned verify --emit "$SUB/v/emit.txt"
assert_exit "$RC" 0 "verify --emit on a match -> 0"
assert_eq "$(cat "$OUT")" "emitted bytes" "--emit prints the verified bytes"

seed_tombstone "$SUB/v/retired.txt"
run_pinned verify "$SUB/v/retired.txt"
assert_exit "$RC" 0 "tombstoned AND absent -> 0"

run_pinned verify "$SUB/v/unknown.txt"
assert_exit "$RC" 10 "no slot -> 10"
assert_contains "$OUT" "no slot" "10 names the state"

printf 'drifted\n' > "$SUB/v/drift.txt"
seed_pin "$SUB/v/drift.txt" "$(digest_of "$SUB/v/drift.txt")"
printf 'drifted differently\n' > "$SUB/v/drift.txt"
run_pinned verify "$SUB/v/drift.txt"
assert_exit "$RC" 11 "content mismatch -> 11"
assert_contains "$OUT" "does not match its approved record" "11 names the mismatch"

printf 'here for now\n' > "$SUB/v/vanish.txt"
seed_pin "$SUB/v/vanish.txt" "$(digest_of "$SUB/v/vanish.txt")"
rm -f "$SUB/v/vanish.txt"
run_pinned verify "$SUB/v/vanish.txt"
assert_exit "$RC" 20 "pinned but missing -> 20"
assert_contains "$OUT" "pinned but missing" "20 names the absence"

printf 'back from the dead\n' > "$SUB/v/risen.txt"
seed_tombstone "$SUB/v/risen.txt"
run_pinned verify "$SUB/v/risen.txt"
assert_exit "$RC" 13 "tombstoned but present -> 13"
assert_contains "$OUT" "retired content resurrected" "13 names the resurrection"

printf 'loose modes\n' > "$SUB/v/loose.txt"
seed_pin "$SUB/v/loose.txt" "$(digest_of "$SUB/v/loose.txt")"
chmod 664 "$SUB/v/loose.txt"
run_pinned verify "$SUB/v/loose.txt"
assert_exit "$RC" 30 "group-writable subject -> 30"
assert_contains "$OUT" "group/other-writable" "30 names the invariant"
chmod 644 "$SUB/v/loose.txt"
run_pinned verify "$SUB/v/loose.txt"
assert_exit "$RC" 0 "remediated mode verifies again"

run_pinned verify "$SUB/v/never/existed/at/all.txt"
assert_exit "$RC" 10 "absent path under a MISSING parent, no slot -> 10 (launch regression)"
assert_contains "$OUT" "no slot" "the missing-parent case still reaches the slot verdict"

# ---------------------------------------------------------------------------
say "S4: review --file ceremony"
# ---------------------------------------------------------------------------
mkdir -p "$SUB/a"
printf 'first ever\n' > "$SUB/a/first.txt"
FIRST_SLOT="$(slot_of "$SUB/a/first.txt")"
assert_absent "$FIRST_SLOT" "precondition: no slot dir before the first approval"
ANS='
y
'
run_pinned review --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "first-ever approval of an unpinned path succeeds (regression)"
assert_contains "$OUT" "first approval" "ceremony announces the first approval"
assert_contains "$OUT" "pin.sha256" "ceremony names the record it wrote"
assert_file "$FIRST_SLOT/pin.sha256" "record file exists"
assert_eq "$(cat "$FIRST_SLOT/pin.sha256")" \
          "$(digest_of "$SUB/a/first.txt")  $SUB/a/first.txt" \
          "record is '<digest>  <path>'"
assert_eq "$(count_state "$FIRST_SLOT")" 1 "slot holds exactly one state file"
# CUSTODY IS OPT-IN. A plain ceremony records a digest and keeps no witness:
# the slot discloses one hash and nothing about the file's content.
assert_absent "$FIRST_SLOT/approved" "a plain review keeps no stored copy"
assert_missing "$OUT" "(+approved copy)" "and does not claim to have written one"
assert_contains "$OUT" "custody:" "the ceremony states custody in both directions"
assert_contains "$OUT" "No copy is kept at rest" "and says what 'none' means before the confirm"
run_pinned verify "$SUB/a/first.txt"
assert_exit "$RC" 0 "the approved file verifies"

ANS=""
run_pinned review --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "re-approving identical bytes needs no answer"
assert_contains "$OUT" "already approved" "re-approval short-circuits"

# ADDING custody is a disclosure decision, so the human confirms it: identical
# bytes stop being a no-op the moment --store changes the custody state.
ANS='
y
'
run_pinned review --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "adding --store to a copy-less slot runs"
assert_missing "$OUT" "already approved" "adding custody defeats the no-op short-circuit"
assert_contains "$OUT" "adds a stored copy" "the note names the custody delta and its direction"
assert_contains "$OUT" "A copy of these bytes is kept beside" \
                "a changing disposition gets the full explanation"
assert_missing "$OUT" "in every lane" "which no longer talks about lanes"
assert_contains "$OUT" "(+approved copy)" "the success line names the copy it wrote"
assert_file "$FIRST_SLOT/approved" "--store writes the witness"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(digest_of "$SUB/a/first.txt")" \
          "the witness is byte-for-byte the approved file"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(awk '{print $1}' "$FIRST_SLOT/pin.sha256")" \
          "the witness re-hashes to the pin beside it"
assert_eq "$(count_state "$FIRST_SLOT")" 1 "the witness is an annotation: no part of the one-state rule"

# The no-op condition is identical bytes AND identical declaration AND
# identical custody -- all three, so this one short-circuits again.
ANS=""
run_pinned review --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "identical bytes with unchanged custody need no answer"
assert_contains "$OUT" "already approved" "unchanged custody keeps the short-circuit"

# Dropping it is equally a decision, and equally loud -- stated before the
# confirm and again in the result.
ANS='
y
'
run_pinned review --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "re-approving a custody slot without --store runs"
assert_missing "$OUT" "already approved" "dropping custody defeats the no-op short-circuit"
assert_contains "$OUT" "drops the slot's stored copy" "the pre-confirm note says the copy is going"
assert_contains "$OUT" "was dropped" "the result line says it went"
assert_absent "$FIRST_SLOT/approved" "a plain re-approve drops the stored copy"

# What custody holds is always what the LAST ceremony displayed.
printf 'second draft\n' > "$SUB/a/first.txt"
ANS='
y
'
run_pinned review --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "re-approving changed bytes with --store succeeds"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(digest_of "$SUB/a/first.txt")" \
          "the witness is the newly approved bytes"
printf 'third draft\n' > "$SUB/a/first.txt"
ANS='
y
'
run_pinned review --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "re-approving again with --store succeeds"
assert_missing "$OUT" "custody change" "unchanged custody needs no custody note"
# STATING custody is one line; EXPLAINING it is a paragraph spent only where
# the ceremony is deciding custody rather than restating it. Here the slot
# already held a copy and --store keeps it: the one-liner, nothing more.
assert_contains "$OUT" "custody:    kept in the slot" "custody is restated on one line"
assert_missing "$OUT" "A copy of these bytes is kept beside" \
               "an unchanged disposition spends no paragraph on it"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(awk '{print $1}' "$FIRST_SLOT/pin.sha256")" \
          "the refreshed witness re-hashes to the new pin"

# A stored witness that does not re-hash is incoherent state, and the ceremony
# is what verify tells you to run -- so it must not short-circuit away.
printf 'tampered\n' > "$FIRST_SLOT/approved"
chmod 600 "$FIRST_SLOT/approved"
ANS='
y
'
run_pinned review --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "re-approving over an incoherent witness runs"
assert_missing "$OUT" "already approved" "a witness that does not re-hash defeats the short-circuit"
assert_contains "$OUT" "does not re-hash to its record" "the note names the incoherence"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(awk '{print $1}' "$FIRST_SLOT/pin.sha256")" \
          "and the ceremony replaces it"

printf 'reinstate me\n' > "$SUB/a/reinstated.txt"
seed_tombstone "$SUB/a/reinstated.txt"
REIN_SLOT="$(slot_of "$SUB/a/reinstated.txt")"
ANS='
y
'
run_pinned review --file "$SUB/a/reinstated.txt"
assert_exit "$RC" 0 "approving over a tombstone succeeds"
assert_contains "$OUT" "approving reinstates this path" "ceremony warns it reinstates"
assert_absent "$REIN_SLOT/tombstone" "tombstone is gone after reinstatement"
assert_eq "$(count_state "$REIN_SLOT")" 1 "reinstated slot holds exactly one state file"

printf 'not this time\n' > "$SUB/a/declined.txt"
DECL_SLOT="$(slot_of "$SUB/a/declined.txt")"
ANS='
n
'
run_pinned review --file "$SUB/a/declined.txt"
assert_exit "$RC" 0 "declining exits 0"
assert_contains "$OUT" "declined; record unchanged" "decline is reported"
assert_eq "$(count_state "$DECL_SLOT")" 0 "declining records nothing"

# --- the gates before each pager --------------------------------------------
# Nothing full-screen arrives unannounced: each file's pager sits behind a
# gate naming WHAT opens and how big it is (which is why every ceremony above
# feeds a blank line before its y/N), and a batch says which item you are on.
mkdir -p "$SUB/a/gate"
printf 'g1\ng2\ng3\n' > "$SUB/a/gate/one.txt"
printf 'g1\ng2\ng3\n' > "$SUB/a/gate/two.txt"
ANS='
y

y
'
run_pinned review --file "$SUB/a/gate/one.txt" --file "$SUB/a/gate/two.txt"
assert_exit "$RC" 0 "a two-file ceremony records both"
assert_contains "$OUT" "[1/2]" "the batch counter names the item under ceremony"
assert_contains "$OUT" "[2/2]" "and moves on with the batch"
assert_contains "$OUT" "full content 3 lines; Enter opens it" \
                "a first approval's gate names the size of what it opens"

printf 'lonely\n' > "$SUB/a/gate/solo.txt"
ANS='
y
'
run_pinned review --file "$SUB/a/gate/solo.txt"
assert_exit "$RC" 0 "a single-file ceremony records"
assert_contains "$OUT" "full content 1 line; Enter opens it" "the singular gate reads as one"
assert_missing "$OUT" "[1/1]" "one --file is not a batch: no counter"

# A VERIFIED baseline turns the pager into a diff, and the gate states the
# diff's magnitude instead of the whole file's length.
cp "$SUB/a/gate/solo.txt" "$FIX/solo-baseline.txt"
printf 'lonely\nno more\n' > "$SUB/a/gate/solo.txt"
ANS='
y
'
run_pinned review --file "$SUB/a/gate/solo.txt" --baseline "$FIX/solo-baseline.txt"
assert_exit "$RC" 0 "a baseline-diff ceremony records"
assert_contains "$OUT" "+1 -0; Enter opens the diff" "the gate states the diff's magnitude"
assert_contains "$OUT" "diff vs the approved baseline" "and the pager is that diff"

# --- the keys summary above a JSON baseline diff ----------------------------
# One line naming WHICH keys changed, computed from whole-document
# flattenings of the two frozen buffers (json_keys_changed) -- a summary,
# never a per-hunk claim -- and failing safe to NO line on non-JSON content,
# malformed JSON, or a missing jq.
assert_missing "$OUT" "keys:" "a non-JSON baseline diff carries no keys line"
printf '{"a":1}\n' > "$FIX/kc-old.json"
printf '{"a":2}\n' > "$FIX/kc-new.json"
if command -v jq >/dev/null 2>&1; then
  run_probe json_keys_changed "$FIX/kc-old.json" "$FIX/kc-new.json"
  assert_exit "$RC" 0 "json_keys_changed answers 0 for two JSON documents"
  assert_eq "$POUT" "$(printf 'changed\t0\ta')" \
            "a key changed on both sides folds to one bare 'changed' row"
  mkdir -p "$SUB/a/keys"
  printf '{\n  "extra": true,\n  "model": "opus",\n  "permissions": {\n    "ask": ["a"]\n  }\n}\n' \
    > "$SUB/a/keys/set.json"
  ANS='
y
'
  run_pinned review --file "$SUB/a/keys/set.json"
  assert_exit "$RC" 0 "fixture: set.json first approval"
  cp "$SUB/a/keys/set.json" "$FIX/keys-baseline.json"
  printf '{\n  "model": "sonnet",\n  "permissions": {\n    "ask": ["a", "b", "c"]\n  }\n}\n' \
    > "$SUB/a/keys/set.json"
  ANS='
y
'
  run_pinned review --file "$SUB/a/keys/set.json" --baseline "$FIX/keys-baseline.json"
  assert_exit "$RC" 0 "a JSON baseline-diff ceremony records"
  assert_contains "$OUT" "keys: extra(-1) model permissions.ask(+2)" \
                  "ONE keys line counts removals and additions, leaves a changed key bare, and folds array leaves to their key"
  # Malformed JSON degrades to the byte diff alone: the summary must fail
  # safe to nothing, never render a wrong structural claim.
  printf '{\n  "model": "opus"\n}\n' > "$SUB/a/keys/broken.json"
  ANS='
y
'
  run_pinned review --file "$SUB/a/keys/broken.json"
  assert_exit "$RC" 0 "fixture: broken.json first approval"
  cp "$SUB/a/keys/broken.json" "$FIX/broken-baseline.json"
  printf '{\n  "model": "opus", oops\n' > "$SUB/a/keys/broken.json"
  ANS='
y
'
  run_pinned review --file "$SUB/a/keys/broken.json" --baseline "$FIX/broken-baseline.json"
  assert_exit "$RC" 0 "a now-malformed JSON file still reviews as bytes"
  assert_contains "$OUT" "diff vs the approved baseline" "the byte diff still renders"
  assert_missing "$OUT" "keys:" "malformed JSON yields no keys line (fail safe to nothing)"
else
  say "  keys-summary JSON cases SKIPPED (no jq in the trusted PATH)"
fi
# jq absent: the structural view answers 1 and emits nothing, so the ceremony
# prints no keys line -- jq stays a hard requirement only where
# --ignore-json-key declares a tolerance. The script pins its OWN trusted
# PATH (and macOS ships /usr/bin/jq), so a caller-env override cannot hide
# jq; a probe variant whose pinned PATH line is rewritten to an empty dir --
# anchored like every other harness sed -- is the honest simulation.
# `command -v jq` is the function's FIRST check, so nothing else needs to
# resolve from that empty dir.
need '^export PATH=/usr/bin:/bin:/usr/sbin:/sbin$' 1 'pinned trusted PATH'
NOJQ="$FIX/nojq-bin"; mkdir -p "$NOJQ"
sed "s#^export PATH=/usr/bin:/bin:/usr/sbin:/sbin\$#export PATH='$NOJQ'#" "$LIB" \
  > "$FIX/nojq-lib.bash"
cat > "$FIX/nojq-probe" <<EOF
#!$HARNESS_BASH
set -euo pipefail
fn="\$1"; shift
args=("\$@")
# shellcheck disable=SC1090
. "$FIX/nojq-lib.bash" probe
"\$fn" \${args[@]+"\${args[@]}"}
EOF
chmod 755 "$FIX/nojq-probe"
RC=0
POUT="$("$FIX/nojq-probe" json_keys_changed "$FIX/kc-old.json" "$FIX/kc-new.json" 2>"$ERRF")" || RC=$?
assert_exit "$RC" 1 "no jq in the trusted PATH -> json_keys_changed answers 1 (no structural view)"
assert_eq "$POUT" "" "and emits nothing, so no keys line can render"

# ---------------------------------------------------------------------------
say "S5: tombstone"
# ---------------------------------------------------------------------------
mkdir -p "$SUB/t"
printf 'still here\n' > "$SUB/t/live.txt"
ANS='
y
'
run_pinned review --file "$SUB/t/live.txt"
assert_exit "$RC" 0 "fixture: live.txt approved"
run_pinned tombstone "$SUB/t/live.txt"
assert_exit "$RC" 1 "tombstone refuses while the path exists"
assert_contains "$OUT" "still exists" "refusal names the reason"

rm -f "$SUB/t/live.txt"
ANS='y
'
run_pinned tombstone "$SUB/t/live.txt"
assert_exit "$RC" 0 "tombstone records once the path is gone"
assert_contains "$OUT" "tombstoned" "ceremony confirms the tombstone"
LIVE_SLOT="$(slot_of "$SUB/t/live.txt")"
assert_file "$LIVE_SLOT/tombstone" "tombstone state file written"
assert_eq "$(count_state "$LIVE_SLOT")" 1 "tombstone replaced the pin (exactly one state)"
ANS=""
run_pinned verify "$SUB/t/live.txt"
assert_exit "$RC" 0 "tombstoned and absent verifies 0"
printf 'resurrected\n' > "$SUB/t/live.txt"
run_pinned verify "$SUB/t/live.txt"
assert_exit "$RC" 13 "the file reappearing turns the verdict into 13"

mkdir -p "$SUB/t/wholesale"
printf 'doomed subtree\n' > "$SUB/t/wholesale/conf.json"
ANS='
y
'
run_pinned review --file "$SUB/t/wholesale/conf.json"
assert_exit "$RC" 0 "fixture: file inside a doomed directory approved"
rm -rf "$SUB/t/wholesale"
ANS='y
'
run_pinned tombstone "$SUB/t/wholesale/conf.json"
assert_exit "$RC" 0 "tombstone works when the parent dir was removed wholesale (regression)"
assert_contains "$OUT" "tombstoned" "wholesale removal is tombstonable"
ANS=""
run_pinned verify "$SUB/t/wholesale/conf.json"
assert_exit "$RC" 0 "the wholesale-removed path now verifies 0"

# ---------------------------------------------------------------------------
say "S6: write_slot_state / malformed slots"
# ---------------------------------------------------------------------------
STATE_SLOT="$FIX/statetest/slot"
TREE_DMODE=755 TREE_FMODE=644 "$PROBE" write_slot_state "$STATE_SLOT" pin.sha256 \
  "0000000000000000000000000000000000000000000000000000000000000000  /x"
assert_file "$STATE_SLOT/pin.sha256" "write_slot_state wrote the pin"
TREE_DMODE=755 TREE_FMODE=644 "$PROBE" write_slot_state "$STATE_SLOT" rev.git \
  "1111111111111111111111111111111111111111"
assert_absent "$STATE_SLOT/pin.sha256" "replacing a pin with a rev removes the old state file"
assert_file "$STATE_SLOT/rev.git" "the new state file is in place"
assert_eq "$(count_state "$STATE_SLOT")" 1 "exactly-one-of invariant holds after replacement"

printf 'two states\n' > "$SUB/malformed.txt"
seed_pin "$SUB/malformed.txt" "$(digest_of "$SUB/malformed.txt")"
seed_tombstone "$SUB/malformed.txt"
MAL_SLOT="$(slot_of "$SUB/malformed.txt")"
assert_eq "$(count_state "$MAL_SLOT")" 2 "fixture: slot really holds two state files"
ANS=""
run_pinned verify "$SUB/malformed.txt"
assert_exit "$RC" 1 "a malformed slot exits off-contract (1, not 0/10)"
assert_contains "$OUT" "malformed slot" "the refusal names the malformation"

# ---------------------------------------------------------------------------
say "S7: list"
# ---------------------------------------------------------------------------
mkdir -p "$SUB/l/sub" "$SUB/l/subx" "$SUB/l/Application Support"
printf 'listed one\n' > "$SUB/l/sub/plain.txt"
printf 'listed two\n' > "$SUB/l/Application Support/x.json"
printf 'listed three\n' > "$SUB/l/subx/nearmiss.txt"
printf 'listed four\n' > "$SUB/l/bracket[1].conf"
seed_pin "$SUB/l/sub/plain.txt"              "$(digest_of "$SUB/l/sub/plain.txt")"
seed_pin "$SUB/l/Application Support/x.json" "$(digest_of "$SUB/l/Application Support/x.json")"
seed_pin "$SUB/l/subx/nearmiss.txt"          "$(digest_of "$SUB/l/subx/nearmiss.txt")"
seed_pin "$SUB/l/bracket[1].conf"            "$(digest_of "$SUB/l/bracket[1].conf")"
seed_tombstone "$SUB/l/never-again.txt"

run_pinned list
assert_exit "$RC" 0 "list exits 0"
assert_contains "$OUT" "$SUB/l/sub/plain.txt" "list decodes a plain path"
assert_contains "$OUT" "$SUB/l/Application Support/x.json" "list decodes a path with spaces"
assert_contains "$OUT" "$SUB/l/bracket[1].conf" "list decodes a path with glob metacharacters"
assert_contains "$OUT" "sha256:" "list names the declared kind, as the digest's label"
assert_missing  "$OUT" "$SUB/l/never-again.txt" "list omits tombstoned slots"
# THE GRAMMAR: a flush-left line is a decoded absolute path (the whole line --
# no un-quoting, whatever the path holds), every other non-blank line is an
# indented `label: value` about the path above it, and blank lines separate
# entries. Asserted structurally, so a stray unindented annotation fails here
# rather than in whatever reads this listing.
GRAMMAR_BAD="$(awk '
    /^[[:space:]]*$/ { next }
    /^[^ ]/          { next }
    /^  [a-z0-9]+: /    { next }
                     { print }' "$OUT")"
if [ -z "$GRAMMAR_BAD" ] && grep -qE '^[^ ]' "$OUT" && grep -qE '^  [a-z0-9]+: ' "$OUT"; then
  ok "the grammar holds: flush-left paths, two-space label fields, nothing else"
else
  fail "list emitted a line that is neither a flush-left path nor an indented field: $GRAMMAR_BAD"
fi

run_pinned list --under "$SUB/l/sub"
assert_exit "$RC" 0 "list --under exits 0"
assert_contains "$OUT" "$SUB/l/sub/plain.txt" "--under keeps paths below the directory"
assert_missing  "$OUT" "$SUB/l/subx/nearmiss.txt" "--under matches at a component boundary (/l/sub is not /l/subx)"
assert_missing  "$OUT" "$SUB/l/bracket[1].conf" "--under filters out unrelated pins"

# CUSTODY is stated on every file entry, held or not: a consumer that asks
# list must never have to stat the slot to learn whether the bytes are there.
# One fixture directory per case, so --under scopes the output to exactly one
# entry and its fields (a global grep could not tell which entry a field
# belongs to).
mkdir -p "$SUB/l/held" "$SUB/l/unheld"
printf 'in custody\n' > "$SUB/l/held/kept.txt"
printf 'not in custody\n' > "$SUB/l/unheld/loose.txt"
seed_pin "$SUB/l/held/kept.txt"     "$(digest_of "$SUB/l/held/kept.txt")"
seed_pin "$SUB/l/unheld/loose.txt"  "$(digest_of "$SUB/l/unheld/loose.txt")"
cp "$SUB/l/held/kept.txt" "$(slot_file_of "$SUB/l/held/kept.txt" approved)"
chmod 640 "$(slot_file_of "$SUB/l/held/kept.txt" approved)"

run_pinned list --under "$SUB/l/held"
assert_exit "$RC" 0 "list exits 0 for a byte-exact slot that holds a copy"
assert_contains "$OUT" "$SUB/l/held/kept.txt" "the path stands alone on the entry's first line"
assert_contains "$OUT" "custody:  kept in the slot" "a held copy is stated without any ignored declaration"
assert_missing  "$OUT" "custody:  none" "and the slot is not reported copy-less"
assert_eq "$(grep -c -v '^ ' "$OUT" || true)" 1 \
          "the path is the entry's only flush-left line; every fact is indented under it"

run_pinned list --under "$SUB/l/unheld"
assert_exit "$RC" 0 "list exits 0 for a slot with no copy"
assert_contains "$OUT" "$SUB/l/unheld/loose.txt" "the path stands alone on the entry's first line"
assert_contains "$OUT" "custody:  none  (re-approve with --store to keep one)" \
                "a copy-less slot says so, and says how to fix it"
assert_missing  "$OUT" "kept in the slot" "and does not claim custody it does not have"
assert_eq "$(grep -c -v '^ ' "$OUT" || true)" 1 \
          "the copy-less entry keeps the same one-path-one-block shape"

# status follows the same custody-on-every-record rule (the block sits
# outside the ignore branch): a byte-exact, declaration-free slot reports
# its custody in both directions.
run_pinned status "$SUB/l/held/kept.txt"
assert_exit "$RC" 0 "status exits 0 for the byte-exact held slot"
assert_contains "$OUT" "custody:" "status reports custody without any ignored declaration"
assert_contains "$OUT" "approved bytes kept in the slot" "and names the held direction"

run_pinned status "$SUB/l/unheld/loose.txt"
assert_exit "$RC" 0 "status exits 0 for the copy-less slot"
assert_contains "$OUT" "custody:" "status reports custody on the copy-less slot too"
assert_contains "$OUT" "or re-approve with --store" "and says how to gain it"

# ---------------------------------------------------------------------------
say "S8: repo review"
# ---------------------------------------------------------------------------
REPO_FIX="$FIX/repofix"
mkdir -p "$REPO_FIX"
hgit() { # scrubbed git against the fixture repo ONLY (never cwd)
  env -i PATH="$PATH" HOME=/var/empty \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -C "$REPO_FIX" -c init.defaultBranch=main -c user.name=harness \
    -c user.email=harness@example.invalid -c commit.gpgsign=false \
    -c core.hooksPath=/dev/null "$@"
}
GIT_OK=0
if hgit init -q >/dev/null 2>&1 && [ "$(hgit rev-parse --show-toplevel 2>/dev/null)" = "$REPO_FIX" ]; then
  GIT_OK=1
  ok "git fixture is its own repository (no parent-repo fall-through)"
else
  fail "git init in scratch failed -- run this harness with the sandbox OFF"
fi

if [ "$GIT_OK" -eq 1 ]; then
  printf 'fixture\n' > "$REPO_FIX/file.txt"
  hgit add file.txt >/dev/null
  hgit commit -q -m "fixture commit" >/dev/null
  HEAD_HASH="$(hgit rev-parse 'HEAD^{commit}')"
  REPO_SLOT="$(slot_of "$REPO_FIX")"

  # REGRESSION (was a KNOWN-BUG lock): a FIRST-EVER repo approval must
  # succeed with no pre-existing slot dir. do_approve used to walk ancestry
  # through the not-yet-created slot (`verify_ancestry "$slot/rev.git"`
  # unconditionally), read the failed stat's empty owner as "not root", and
  # refuse every brand-new repo -- the same defect review --file fixed
  # with its `[ -d "$slot" ]` branch (see S4). The slot dir is deliberately
  # NOT pre-created here: its absence is the case under test.
  ANS='
y
'
  run_pinned review "$REPO_FIX"
  assert_exit "$RC" 0 "first-ever repo approval succeeds (no slot dir pre-created)"
  assert_contains "$OUT" "full tree at" "first approval shows the full tree"
  assert_contains "$OUT" "rev.git" "ceremony names the record it wrote"
  # LABEL OWNERSHIP: a source prefix names whose fact a row states, so the
  # revision under ceremony -- which is nobody's record yet -- is the
  # candidate, not a bare "commit".
  assert_contains "$OUT" "git HEAD:" "an untagged ceremony states whose fact the revision is"
  assert_file "$REPO_SLOT/rev.git" "rev.git written"
  assert_eq "$(cat "$REPO_SLOT/rev.git")" "$HEAD_HASH" "rev.git holds the approved commit"
  assert_eq "$(count_state "$REPO_SLOT")" 1 "repo slot holds exactly one state file"

  # The generic resolver (S11) and the repo ceremony must key the SAME dir:
  # one canonicalization, one encoding, no consumer-visible drift.
  ANS=""
  run_pinned slot "$REPO_FIX"
  assert_exit "$RC" 0 "slot on a repo exits 0"
  assert_eq "$(cat "$OUT")" "$REPO_SLOT" "slot names the very dir the repo ceremony wrote"

  ANS=""
  run_pinned status "$REPO_FIX"
  assert_exit "$RC" 0 "status exits 0"
  assert_contains "$OUT" "HEAD is approved" "status reports the pin as approved"

  ANS=""
  run_pinned review "$REPO_FIX"
  assert_exit "$RC" 0 "re-approving the same HEAD needs no answer"
  assert_contains "$OUT" "already pinned" "re-approval short-circuits"

  printf 'second\n' > "$REPO_FIX/file.txt"
  hgit commit -q -am "second commit" >/dev/null
  ANS=""
  run_pinned status "$REPO_FIX"
  assert_exit "$RC" 0 "status after a new commit exits 0"
  assert_contains "$OUT" "HEAD is not approved" "status reports drift from the pin"

  run_pinned list
  assert_contains "$OUT" "git" "list shows the repo pin's declared kind"
  assert_contains "$OUT" "$REPO_FIX" "list shows the repo path"

  # read_rev's length invariant, on the repo slot itself (last: it wrecks it).
  printf 'deadbeef\n' > "$REPO_SLOT/rev.git"
  ANS=""
  run_pinned status "$REPO_FIX"
  assert_exit "$RC" 1 "a short rev.git is refused by read_rev"
  assert_contains "$OUT" "bad hash length" "the refusal names the length invariant"
fi

# Slot parsing without git: hand-written rev.git slots at non-repo paths.
seed_state "$SUB/handwritten.conf" rev.git "1234567890abcdef1234567890abcdef12345678"
ANS=""
run_pinned status "$SUB/handwritten.conf"
assert_exit "$RC" 0 "a well-formed hand-written rev.git slot parses"
assert_contains "$OUT" "1234567890abcdef1234567890abcdef12345678" "status prints the recorded rev"
assert_contains "$OUT" "a repo pin at a non-directory path" "status flags the shape mismatch"

seed_state "$SUB/corruptrev.conf" rev.git "nothex"
ANS=""
run_pinned list
assert_exit "$RC" 0 "list survives a corrupt rev slot"
assert_contains "$OUT" "CORRUPT" "list flags a corrupt rev slot instead of printing a digest"

# ---------------------------------------------------------------------------
say "S8b: batch repo review (multiple repos, one invocation)"
# ---------------------------------------------------------------------------
if [ "$GIT_OK" -eq 1 ]; then
  bgit() { # repo git-args... -- scrubbed git against ONE named fixture repo
    local r="$1"; shift
    env -i PATH="$PATH" HOME=/var/empty \
      GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
      git -C "$r" -c init.defaultBranch=main -c user.name=harness \
      -c user.email=harness@example.invalid -c commit.gpgsign=false \
      -c core.hooksPath=/dev/null "$@"
  }
  REPO_A="$FIX/batch-a"; REPO_B="$FIX/batch-b"
  mkdir -p "$REPO_A" "$REPO_B"
  bgit "$REPO_A" init -q; printf 'a1\n' > "$REPO_A/f"; bgit "$REPO_A" add f; bgit "$REPO_A" commit -q -m a1
  bgit "$REPO_B" init -q; printf 'b1\n' > "$REPO_B/f"; bgit "$REPO_B" add f; bgit "$REPO_B" commit -q -m b1
  A_SLOT="$(slot_of "$REPO_A")"; B_SLOT="$(slot_of "$REPO_B")"

  # Two first-ever approvals in ONE invocation: sequential ceremonies, two
  # answers on one stdin, one summary line.
  ANS='
y

y
'
  run_pinned review "$REPO_A" "$REPO_B"
  assert_exit "$RC" 0 "batch review of two repos exits 0"
  assert_file "$A_SLOT/rev.git" "first repo's rev.git written"
  assert_file "$B_SLOT/rev.git" "second repo's rev.git written"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$(bgit "$REPO_A" rev-parse 'HEAD^{commit}')" "first pin holds repo A's HEAD"
  assert_eq "$(cat "$B_SLOT/rev.git")" "$(bgit "$REPO_B" rev-parse 'HEAD^{commit}')" "second pin holds repo B's HEAD"
  assert_contains "$OUT" "2 approved, 0 declined, 0 already pinned" "batch summary counts both"

  # A decline skips ONLY that repo (the file ceremony's contract): repo A
  # declined keeps its old pin, repo B is approved, exit stays 0.
  A_OLD="$(cat "$A_SLOT/rev.git")"
  printf 'a2\n' > "$REPO_A/f"; bgit "$REPO_A" commit -q -am a2
  printf 'b2\n' > "$REPO_B/f"; bgit "$REPO_B" commit -q -am b2
  ANS='
n

y
'
  run_pinned review "$REPO_A" "$REPO_B"
  assert_exit "$RC" 0 "a mid-batch decline does not abort the batch"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$A_OLD" "declined repo keeps its old pin"
  assert_eq "$(cat "$B_SLOT/rev.git")" "$(bgit "$REPO_B" rev-parse 'HEAD^{commit}')" "later repo still approved"
  assert_contains "$OUT" "1 approved, 1 declined, 0 already pinned" "summary counts the decline"

  # Already-pinned repos are counted, never re-asked: catch repo A up, then
  # run the batch again -- both at their pins, no answer is consumed.
  ANS='
y
'
  run_pinned review "$REPO_A"
  assert_exit "$RC" 0 "catch-up review of the declined repo"
  ANS=""
  run_pinned review "$REPO_A" "$REPO_B"
  assert_exit "$RC" 0 "an all-pinned batch exits 0"
  assert_contains "$OUT" "0 approved, 0 declined, 2 already pinned" "summary counts already-pinned repos"

  # SINGLE-repo contract unchanged: already-pinned exits 0 with no summary
  # line; a decline still exits 2.
  ANS=""
  run_pinned review "$REPO_A"
  assert_exit "$RC" 0 "single already-pinned repo still exits 0"
  assert_missing "$OUT" "declined," "single-repo review prints no batch summary"
  printf 'a3\n' > "$REPO_A/f"; bgit "$REPO_A" commit -q -am a3
  ANS='
n
'
  run_pinned review "$REPO_A"
  assert_exit "$RC" 2 "a single-repo decline still exits 2"
  assert_contains "$OUT" "aborted; pin unchanged" "single decline keeps its message"

  # Selector and evidence flags bind to one repo; a batch refuses them.
  ANS=""
  run_pinned review "$REPO_A" "$REPO_B" --tag v1
  assert_exit "$RC" 1 "--tag with two repos is refused"
  assert_contains "$OUT" "bind to one repo" "the refusal names the rule"
  ANS=""
  run_pinned review "$REPO_A" "$REPO_B" --trust
  assert_exit "$RC" 1 "--trust with two repos is refused"
fi

# ---------------------------------------------------------------------------
say "S8c: upgrade (review stale flake inputs, then deploy)"
# ---------------------------------------------------------------------------
# upgrade chains into deploy, and deploy hard-requires the per-OS rebuild
# tool; skip the section on a machine without one (deploy itself is a
# documented harness gap -- these cases cover upgrade's ceremony phase and
# the dry-run/refusal surface, never an actual rebuild).
REBUILD_TOOL="/run/current-system/sw/bin/darwin-rebuild"
[ -x "$REBUILD_TOOL" ] || REBUILD_TOOL="/run/current-system/sw/bin/nixos-rebuild"
if [ "$GIT_OK" -eq 1 ] && [ -x "$REBUILD_TOOL" ]; then
  A_PIN="$(cat "$A_SLOT/rev.git")"
  B_PIN="$(cat "$B_SLOT/rev.git")"
  cat > "$FIX/flake.nix" <<EOF
{
  inputs.batch-a.url = "git+file://$REPO_A?ref=refs/heads/main&rev=$A_PIN";
  inputs.batch-b.url = "git+file://$REPO_B?ref=refs/heads/main&rev=$B_PIN";
}
EOF

  # Dry run: the stale repo is highlighted, the one at its pin is present
  # but quiet, no ceremony runs, nothing recorded.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "upgrade --dry-run exits 0"
  assert_contains "$OUT" "Inputs in $FIX/flake.nix:" "the plan names the flake it read"
  assert_row "$OUT" "review:" "$REPO_A" "the stale repo is the highlighted row"
  assert_row "$OUT" "at pin:" "$REPO_B" "the input at its pin is a quiet row, not an omission"
  assert_contains "$OUT" "Dry run: no ceremonies" "no ceremony in a dry run"
  assert_contains "$OUT" "Dry run -- nothing executed" "deploy stays a preview"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$A_PIN" "dry run records nothing"

  # Full run: the ceremony approves the stale repo (forced batch contract:
  # a summary even for one repo, so a decline could fall through to
  # deploy), then deploy wants to sync the flake and stops at its
  # confirmation gate -- the harness has no tty, so that gate is the
  # no-tty refusal, and no root command ever runs.
  ANS='
y
'
  run_pinned upgrade --flake "$FIX/flake.nix"
  assert_exit "$RC" 2 "deploy's confirmation gate aborts with 2"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$(bgit "$REPO_A" rev-parse 'HEAD^{commit}')" "the ceremony pinned the stale repo"
  assert_contains "$OUT" "1 approved, 0 declined, 0 already pinned" "upgrade forces the batch contract for one repo"
  assert_contains "$OUT" "no tty for confirmation" "deploy stops at its confirmation gate"
  assert_contains "$FIX/flake.nix" "rev=$A_PIN" "the flake file was not rewritten"

  # Nothing stale: the second round has no ceremonies to offer -- and says
  # so under a list that still holds every input.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "an up-to-date upgrade dry run exits 0"
  assert_contains "$OUT" "nothing to approve" "no stale inputs reported"
  assert_contains "$OUT" "every pinned input is at its approved rev" \
    "an all-quiet plan keeps the at-their-pins wording"
  assert_row "$OUT" "at pin:" "$REPO_A" "the approved repo is now a quiet row"
  assert_row "$OUT" "at pin:" "$REPO_B" "and so is the one that never moved"
  assert_no_row "$OUT" "review:" "$REPO_A" "with nothing highlighted for approval"

  # A tag-declared slot is never plain-approved: it is listed for manual
  # review --tag and the plain-review list stays empty. The tag is a
  # REAL one at the approved rev -- deploy's own live-tag cross-check
  # refuses a declared tag it cannot find (a distinct, correct refusal
  # this case is not about).
  printf 'b3\n' > "$REPO_B/f"; bgit "$REPO_B" commit -q -am b3
  bgit "$REPO_B" tag v9 "$B_PIN"
  printf 'v9\n' > "$B_SLOT/tag"
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "a tag-declared stale input does not break upgrade"
  assert_contains "$OUT" "review --tag by hand" "tag-declared slot routed to manual approval"
  assert_no_row "$OUT" "review:" "$REPO_B" "a tag-declared slot is never highlighted for a plain review"
  assert_row "$OUT" "skipped:" "$REPO_B" "it is a skipped row instead"
  rm -f "$B_SLOT/tag"
  bgit "$REPO_B" tag -d v9 >/dev/null

  # A tag-declared slot whose HEAD carries EXACTLY ONE release tag joins
  # the batch: the ceremony approves that commit under that name, and the
  # declaration follows the release (v9 -> v10).
  printf 'v9\n' > "$B_SLOT/tag"
  bgit "$REPO_B" tag v10
  ANS='
y
'
  run_pinned upgrade --flake "$FIX/flake.nix"
  assert_exit "$RC" 2 "tagged upgrade reaches deploy's confirmation gate"
  assert_contains "$OUT" "(release tag v10)" "the plan names the HEAD release"
  assert_eq "$(cat "$B_SLOT/rev.git")" "$(bgit "$REPO_B" rev-parse 'HEAD^{commit}')" "the tagged repo pinned at its release"
  assert_eq "$(cat "$B_SLOT/tag")" "v10" "the declaration followed the release"

  # Several tags at HEAD is ambiguity, never a guess.
  printf 'b4\n' > "$REPO_B/f"; bgit "$REPO_B" commit -q -am b4
  bgit "$REPO_B" tag v12; bgit "$REPO_B" tag v13
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "ambiguous HEAD tags do not break upgrade"
  assert_contains "$OUT" "no single release tag at HEAD" "several tags at HEAD route to manual"
  bgit "$REPO_B" tag -d v12 >/dev/null; bgit "$REPO_B" tag -d v13 >/dev/null

  # THE ANCESTRY FLOOR (S8f) is upgrade's admission rule: an automatic
  # ceremony only ever covers a FORWARD checkout. A checkout sitting behind
  # its pin, or off the pinned line entirely, is named in the plan with the
  # flag that would declare it and never joins the batch. (The backward one
  # is also the state the old commit-count staleness test could not see at
  # all: `rev-list --count <pin>..HEAD` answered 0 for it.)
  REPO_BK="$FIX/upg-back"; REPO_DV="$FIX/upg-div"; REPO_FW="$FIX/upg-fwd"
  mkdir -p "$REPO_BK" "$REPO_DV" "$REPO_FW"
  for ur in "$REPO_BK" "$REPO_DV" "$REPO_FW"; do
    bgit "$ur" init -q
    printf 'u1\n' > "$ur/f"; bgit "$ur" add f; bgit "$ur" commit -q -m u1
    printf 'u2\n' > "$ur/f"; bgit "$ur" commit -q -am u2
  done
  BK_PIN="$(bgit "$REPO_BK" rev-parse 'HEAD^{commit}')"
  DV_PIN="$(bgit "$REPO_DV" rev-parse 'HEAD^{commit}')"
  FW_PIN="$(bgit "$REPO_FW" rev-parse 'HEAD~1^{commit}')"
  seed_state "$REPO_BK" rev.git "$BK_PIN"
  seed_state "$REPO_DV" rev.git "$DV_PIN"
  seed_state "$REPO_FW" rev.git "$FW_PIN"
  bgit "$REPO_BK" reset --hard -q HEAD~1
  bgit "$REPO_DV" checkout -q -b side HEAD~1
  printf 'u3\n' > "$REPO_DV/f"; bgit "$REPO_DV" commit -q -am u3
  cat > "$FIX/flake3.nix" <<EOF
{
  inputs.upg-back.url = "git+file://$REPO_BK?rev=$BK_PIN";
  inputs.upg-div.url = "git+file://$REPO_DV?rev=$DV_PIN";
  inputs.upg-fwd.url = "git+file://$REPO_FW?rev=$FW_PIN";
}
EOF
  ANS=""
  run_pinned upgrade --flake "$FIX/flake3.nix" --dry-run
  assert_exit "$RC" 0 "a plan holding refused repos still exits 0"
  assert_contains "$OUT" "checkout is backward of the pin -- review --backward by hand" \
    "a backward checkout is refused in the plan"
  assert_contains "$OUT" "checkout diverged from the pin -- review --diverged by hand" \
    "a diverged checkout is refused in the plan"
  assert_row "$OUT" "review:" "$REPO_FW" "the forward repo is the one highlighted for approval"
  assert_no_row "$OUT" "review:" "$REPO_BK" "the backward one is not"
  assert_no_row "$OUT" "review:" "$REPO_DV" "and neither is the diverged one"

  ANS='
y
'
  run_pinned upgrade --flake "$FIX/flake3.nix"
  assert_exit "$RC" 2 "the mixed upgrade reaches deploy's confirmation gate"
  assert_contains "$OUT" "1 approved, 0 declined, 0 already pinned" \
    "only the forward repo got a ceremony"
  assert_eq "$(cat "$(slot_of "$REPO_FW")/rev.git")" "$(bgit "$REPO_FW" rev-parse 'HEAD^{commit}')" \
    "the forward repo was approved"
  assert_eq "$(cat "$(slot_of "$REPO_BK")/rev.git")" "$BK_PIN" "the backward repo's pin is untouched"
  assert_eq "$(cat "$(slot_of "$REPO_DV")/rev.git")" "$DV_PIN" "the diverged repo's pin is untouched"

  # The round done, the forward repo is a quiet at-pin row BESIDE the two
  # refused ones -- and a plan with nothing to approve but something refused
  # must not claim every input is at its pin.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake3.nix" --dry-run
  assert_exit "$RC" 0 "the follow-up plan exits 0"
  assert_row "$OUT" "at pin:" "$REPO_FW" "the approved repo drops to a quiet row"
  assert_row "$OUT" "refused:" "$REPO_BK" "beside the refused backward checkout"
  assert_contains "$OUT" "no input above is a forward checkout upgrade may cover" \
    "and the summary stays honest about why nothing is actionable"
  assert_missing "$OUT" "every pinned input is at its approved rev" \
    "the at-their-pins wording is not claimed over refused rows"

  # Availability probe: a pin the checkout no longer holds is warned about
  # EARLY (status and deploy's scan), instead of surfacing as a nix fetch
  # error mid-rebuild. A warning, never a refusal: nix's store cache may
  # still satisfy the input.
  REPO_C="$FIX/batch-c"
  mkdir -p "$REPO_C"
  bgit "$REPO_C" init -q; printf 'c1\n' > "$REPO_C/f"; bgit "$REPO_C" add f; bgit "$REPO_C" commit -q -m c1
  FAKE_REV="1234567890abcdef1234567890abcdef12345678"
  seed_state "$REPO_C" rev.git "$FAKE_REV"
  ANS=""
  run_pinned status "$REPO_C"
  assert_exit "$RC" 0 "status on a repo whose pin is gone still reports"
  assert_contains "$OUT" "missing from this checkout" "status warns the pinned rev is unfetchable"
  cat > "$FIX/flake2.nix" <<EOF
{
  inputs.batch-c.url = "git+file://$REPO_C?rev=$FAKE_REV";
}
EOF
  ANS=""
  run_pinned deploy --flake "$FIX/flake2.nix" --dry-run
  assert_exit "$RC" 0 "deploy dry run tolerates the missing rev"
  assert_contains "$OUT" "missing from the checkout" "deploy warns early about the unfetchable pin"

  # EVERY input is a row. An input with no rev=, a repo with no pin slot and
  # a pinned path with no checkout are all states upgrade will not act on --
  # and all states the plan must SHOW, because an omitted line is
  # indistinguishable from a tool that never looked at the input. Deploy
  # stays the authority on them; the plan only says they are there.
  REPO_NR="$FIX/upg-norev"; REPO_NS="$FIX/upg-noslot"; REPO_GONE="$FIX/upg-gone"
  mkdir -p "$REPO_NR" "$REPO_NS"
  for ur in "$REPO_NR" "$REPO_NS"; do
    bgit "$ur" init -q
    printf 'n1\n' > "$ur/f"; bgit "$ur" add f; bgit "$ur" commit -q -m n1
  done
  NR_REV="$(bgit "$REPO_NR" rev-parse 'HEAD^{commit}')"
  NS_REV="$(bgit "$REPO_NS" rev-parse 'HEAD^{commit}')"
  seed_state "$REPO_NR" rev.git "$NR_REV"
  seed_state "$REPO_GONE" rev.git "$NS_REV"
  cat > "$FIX/flake4.nix" <<EOF
{
  inputs.upg-norev.url = "git+file://$REPO_NR?ref=refs/heads/main";
  inputs.upg-noslot.url = "git+file://$REPO_NS?rev=$NS_REV";
  inputs.upg-gone.url = "git+file://$REPO_GONE?rev=$NS_REV";
}
EOF
  ANS=""
  run_pinned upgrade --flake "$FIX/flake4.nix" --dry-run
  assert_exit "$RC" 0 "a plan of inputs upgrade cannot act on exits 0"
  assert_row "$OUT" "no pin:" "$REPO_NR" "an input without rev= is a row"
  assert_row "$OUT" "no slot:" "$REPO_NS" "an input without a pin slot is a row"
  assert_row "$OUT" "no checkout:" "$REPO_GONE" "a pinned path with no checkout is a row"
  assert_contains "$OUT" "nothing to approve" "none of the three is actionable"
  assert_contains "$OUT" "Dry run -- nothing executed" "and the round still falls through to deploy"

  # Malformed argv dies before anything runs.
  ANS=""
  run_pinned upgrade --bogus
  assert_exit "$RC" 1 "unknown upgrade option is usage"
else
  say "S8c: SKIPPED (no git fixture or no rebuild tool)"
fi

# ---------------------------------------------------------------------------
say "S8d: per-commit diffstat in the commits-since listing"
# ---------------------------------------------------------------------------
# The listing is orientation a trust decision is read against, so the counts
# are asserted EXACTLY, alignment included: the hash column is stripped
# (%h picks its own length) and the rest is compared as one block.
if [ "$GIT_OK" -eq 1 ]; then
  REPO_D="$FIX/statfix"
  mkdir -p "$REPO_D"
  bgit "$REPO_D" init -q
  printf 'l1\nl2\nl3\n' > "$REPO_D/a.txt"
  bgit "$REPO_D" add a.txt; bgit "$REPO_D" commit -q -m "d1 base"
  D_SLOT="$(slot_of "$REPO_D")"
  ANS='
y
'
  run_pinned review "$REPO_D"
  assert_exit "$RC" 0 "diffstat fixture pins its base commit"
  D_PIN="$(cat "$D_SLOT/rev.git")"

  # Known counts, newest last: 2 files/+3/-0, then a side branch (1/+4/-0),
  # a rewrite on main (1/+1/-1), the merge (no per-commit diff), and a
  # binary add (1 file, no line counts).
  printf 'l4\n' >> "$REPO_D/a.txt"
  printf 'b1\nb2\n' > "$REPO_D/b.txt"
  bgit "$REPO_D" add a.txt b.txt; bgit "$REPO_D" commit -q -m "d2 two files"
  bgit "$REPO_D" checkout -q -b side
  printf 'c1\nc2\nc3\nc4\n' > "$REPO_D/c.txt"
  bgit "$REPO_D" add c.txt; bgit "$REPO_D" commit -q -m "d3 side"
  bgit "$REPO_D" checkout -q main
  printf 'l1\nl2\nCHANGED\nl4\n' > "$REPO_D/a.txt"
  bgit "$REPO_D" commit -q -am "d4 main"
  bgit "$REPO_D" merge -q --no-ff -m "d5 merge side" side
  printf 'bin\000data\n' > "$REPO_D/d.bin"
  bgit "$REPO_D" add d.bin; bgit "$REPO_D" commit -q -m "d6 binary"
  D_HEAD="$(bgit "$REPO_D" rev-parse 'HEAD^{commit}')"

  ANS='
y
'
  run_pinned review "$REPO_D"
  assert_exit "$RC" 0 "review over the diffstat range exits 0"
  assert_eq "$(cat "$D_SLOT/rev.git")" "$D_HEAD" "the range was approved"

  # The block is everything between the listing header and the blank line
  # before the diff; the hash column varies in width, so it is dropped.
  D_LINES="$(awk '/^--- commits since last approval ---$/ { f = 1; next }
                  /^$/ { f = 0 } f' "$OUT" | sed 's/^[0-9a-f]*  //')"
  assert_eq "$D_LINES" 'd6 binary       1 file  +0 -0
d5 merge side        -   -  -
d4 main         1 file  +1 -1
d3 side         1 file  +4 -0
d2 two files   2 files  +3 -0' "the ceremony lists aligned per-commit counts, pluralized"

  # The pre-sudo preview is unreachable from the stub (its elevation gate is
  # sed'd to `if false`), and it differs from the ceremony only by the
  # indent argument -- so the shared helper is driven directly for it.
  RC=0
  repo="$REPO_D" "$PROBE" print_commit_range "$D_PIN" "$D_HEAD" '  ' >"$OUT" 2>"$ERRF" || RC=$?
  assert_exit "$RC" 0 "the preview form of the listing exits 0"
  assert_contains "$OUT" '  d2 two files   2 files  +3 -0' "the preview indents the same enriched line"
  assert_missing  "$OUT" 'd2 two files  2 files' "the preview does not lose the subject padding"

  # A merge inside the range must not poison its neighbours' counts: the
  # placeholder row is the only one without numbers.
  assert_eq "$(grep -c -e '-  -$' "$OUT")" 1 "exactly one placeholder row (the merge)"
else
  say "S8d: SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S8e: approve --step (per-commit staged approval)"
# ---------------------------------------------------------------------------
# The walk's contract is that every yes leaves a COHERENT record: the pin
# advances one commit at a time, so a stop midway rests it at the last commit
# actually read. Each case below re-seeds the pin at the base commit and drives
# the whole walk from $ANS.
#
# The pre-sudo preview's mirrored refusals are NOT reachable here (the
# elevation gate is sed'd to `if false`) -- the same gap the header records for
# the preview as a whole. The root-side refusals, which are the authoritative
# ones, are all covered.
if [ "$GIT_OK" -eq 1 ]; then
  REPO_E="$FIX/stepfix"
  mkdir -p "$REPO_E"
  bgit "$REPO_E" init -q
  printf 'b1\nb2\nb3\n' > "$REPO_E/base.txt"
  bgit "$REPO_E" add base.txt; bgit "$REPO_E" commit -q -m "e0 base"
  E_BASE="$(bgit "$REPO_E" rev-parse 'HEAD^{commit}')"
  E_SLOT="$(slot_of "$REPO_E")"

  # Three commits with distinct, greppable content. Known counts over the
  # whole range: base.txt +1 -1, e1.txt +1, e2.txt +2, e3.txt +1
  # -> 4 files, +5, -1.
  printf 'E1LINE\n' > "$REPO_E/e1.txt"
  bgit "$REPO_E" add e1.txt; bgit "$REPO_E" commit -q -m "e1 first"
  E_C1="$(bgit "$REPO_E" rev-parse 'HEAD^{commit}')"
  printf 'E2LINE\nE2MORE\n' > "$REPO_E/e2.txt"
  printf 'b1\nE2EDIT\nb3\n' > "$REPO_E/base.txt"
  bgit "$REPO_E" add e2.txt base.txt; bgit "$REPO_E" commit -q -m "e2 second"
  E_C2="$(bgit "$REPO_E" rev-parse 'HEAD^{commit}')"
  printf 'E3LINE\n' > "$REPO_E/e3.txt"
  bgit "$REPO_E" add e3.txt; bgit "$REPO_E" commit -q -m "e3 third"
  E_HEAD="$(bgit "$REPO_E" rev-parse 'HEAD^{commit}')"

  # --- three yeses: the pin lands on HEAD, one step per commit -------------
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS='
y

y

y
'
  run_pinned review "$REPO_E" --step
  assert_exit "$RC" 0 "a fully approved walk exits 0"
  assert_eq "$(cat "$E_SLOT/rev.git")" "$E_HEAD" "three yeses walk the pin to HEAD"
  assert_contains "$OUT" "--- step 1/3 ---" "the walk numbers its steps"
  assert_contains "$OUT" "--- step 3/3 ---" "the walk reaches the last step"
  assert_contains "$OUT" "approved 3 of 3 commits" "the summary counts every step"
  assert_eq "$(grep -c '✓ pin advanced:' "$OUT")" 3 "every yes confirms an advanced pin"

  # Each step shows ONLY its own commit: step 2 carries e2's content and
  # neither e1's (already approved) nor e3's (not yet offered).
  awk '/^--- step 2\/3 ---$/ { f = 1; next } /^--- step 3\/3 ---$/ { f = 0 } f' \
    "$OUT" > "$FIX/step2"
  assert_contains "$FIX/step2" "E2LINE" "step 2 shows its own commit's content"
  assert_contains "$FIX/step2" "E2EDIT" "step 2 shows its own commit's edits"
  assert_missing  "$FIX/step2" "E3LINE" "step 2 does not leak the next commit"
  assert_missing  "$FIX/step2" "E1LINE" "step 2 does not repeat the approved commit"

  # The closing aggregate is the composition-risk mitigation: the whole
  # sitting's totals, exactly.
  assert_contains "$OUT" "total: 4 files +5 -1" "the summary totals the approved range"
  assert_missing  "$OUT" "remaining:" "a completed walk has nothing remaining"
  assert_missing  "$OUT" "✓ approved:" "the walk replaces the single-approval line"

  # --- yes then no: the pin rests where reading stopped --------------------
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS='
y

n
'
  run_pinned review "$REPO_E" --step
  assert_exit "$RC" 0 "a partial walk still exits 0 (the pin did advance)"
  assert_eq "$(cat "$E_SLOT/rev.git")" "$E_C1" "the pin rests at the last approved commit"
  assert_contains "$OUT" "approved 1 of 3 commits" "the summary counts the partial walk"
  assert_contains "$OUT" "remaining: 2 commits" "the summary names what is left"
  assert_contains "$OUT" "total: 1 file +1 -0" "the aggregate covers only the approved range, singular"
  assert_missing  "$OUT" "--- step 3/3 ---" "a decline stops the walk instead of skipping"

  # --- two yeses then no: the singular remainder reads as one --------------
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS='
y

y

n
'
  run_pinned review "$REPO_E" --step
  assert_exit "$RC" 0 "a two-step walk exits 0"
  assert_contains "$OUT" "approved 2 of 3 commits" "the summary counts both steps"
  assert_contains "$OUT" "remaining: 1 commit " "one leftover commit is singular"
  assert_missing  "$OUT" "remaining: 1 commits" "and never plural"

  # --- a first no: nothing changes, exit 2 (the single-repo contract) ------
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS='
n
'
  run_pinned review "$REPO_E" --step
  assert_exit "$RC" 2 "a walk that approves nothing exits 2"
  assert_eq "$(cat "$E_SLOT/rev.git")" "$E_BASE" "a declined walk leaves the pin alone"
  assert_contains "$OUT" "approved 0 of 3 commits" "the summary reports an empty walk"
  assert_contains "$OUT" "pin unchanged" "the summary says the pin did not move"
  assert_missing  "$OUT" "total:" "no aggregate for a walk that approved nothing"

  # --- a stepped yes clears a declared release name ------------------------
  seed_state "$REPO_E" rev.git "$E_BASE"
  printf 'v1\n' > "$E_SLOT/tag"
  ANS='
y

n
'
  run_pinned review "$REPO_E" --step
  assert_exit "$RC" 0 "a stepped review over a tag-declared slot exits 0"
  assert_absent "$E_SLOT/tag" "a stepped yes clears the declared tag"

  # --- --tag moves the endpoint: the walk ends at the tag's commit ---------
  # The name is declared only when the walk actually approves that commit;
  # the commit past the tag (e3) must never be offered.
  bgit "$REPO_E" tag v9 "$E_C2"
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS='
y

y
'
  run_pinned review "$REPO_E" --step --tag v9
  assert_exit "$RC" 0 "a stepped walk to a tag exits 0"
  assert_eq "$(cat "$E_SLOT/rev.git")" "$E_C2" "the pin rests at the tag's commit, not HEAD"
  assert_eq "$(cat "$E_SLOT/tag")" "v9" "reaching the endpoint declares the name"
  assert_contains "$OUT" "approved 2 of 2 commits" "the walk is exactly pin..tag"
  assert_missing  "$OUT" "E3LINE" "the commit past the tag is never offered"

  # Stopping early leaves the slot rev-only and says so.
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS='
y

n
'
  run_pinned review "$REPO_E" --step --tag v9
  assert_exit "$RC" 0 "an early stop below the tag still exits 0"
  assert_eq "$(cat "$E_SLOT/rev.git")" "$E_C1" "the pin rests where reading stopped"
  assert_absent "$E_SLOT/tag" "an unreached name is not declared"
  assert_contains "$OUT" "declared name v9 not reached; the slot stays rev-only" \
    "the summary says the name was not declared"

  # --- refusals (root-side: the authoritative half) ------------------------
  seed_state "$REPO_E" rev.git "$E_BASE"
  ANS=""
  run_pinned review "$REPO_E" --step --trust
  assert_exit "$RC" 1 "--step with --trust is refused"
  assert_contains "$OUT" "--trust skips review" "the refusal names the contradiction"
  ANS=""
  run_pinned review "$REPO_E" --step --signed-tag v1
  assert_exit "$RC" 1 "--step with --signed-tag is refused"
  assert_contains "$OUT" "signature evidence has no per-commit reading" "the refusal names the reason"
  ANS=""
  run_pinned review "$REPO_E" "$REPO_A" --step
  assert_exit "$RC" 1 "--step with two repos is refused"
  assert_contains "$OUT" "bind to one repo" "the refusal names the one-repo rule"
  ANS=""
  run_pinned review --file "$SUB/a.conf" --step
  assert_exit "$RC" 1 "--step with --file is refused"
  assert_contains "$OUT" "its own ceremony" "the refusal names the file ceremony"

  # upgrade's internal batch contract cannot host an interactive walk.
  RC=0
  printf '' > "$FIX/stdin"
  APPROVE_BATCH=1 "$STUB" review "$REPO_E" --step <"$FIX/stdin" >"$OUT" 2>&1 || RC=$?
  assert_exit "$RC" 1 "--step inside a batch review is refused"
  assert_contains "$OUT" "does not run inside a batch review" "the refusal names the batch rule"

  # A first approval has no pin to step from.
  REPO_F="$FIX/stepfix-new"
  mkdir -p "$REPO_F"
  bgit "$REPO_F" init -q; printf 'f1\n' > "$REPO_F/f"; bgit "$REPO_F" add f
  bgit "$REPO_F" commit -q -m f1
  ANS=""
  run_pinned review "$REPO_F" --step
  assert_exit "$RC" 1 "--step on a never-approved repo is refused"
  assert_contains "$OUT" "review without --step" "the refusal points at the plain ceremony"
  assert_absent "$(slot_of "$REPO_F")/rev.git" "the refused walk recorded nothing"

  # The pin ahead of HEAD (reversed history) has no commits to walk. The
  # ancestry floor (S8f) now refuses that endpoint before the walk is
  # entered, so the refusal a reviewer meets is the lattice's -- naming the
  # class and the flag that would declare it. --step's own "not behind HEAD"
  # message stays in the script as the walk's internal belt-and-braces.
  seed_state "$REPO_E" rev.git "$E_HEAD"
  bgit "$REPO_E" branch -q back "$E_C2"
  bgit "$REPO_E" checkout -q back
  ANS=""
  run_pinned review "$REPO_E" --step
  assert_exit "$RC" 1 "a pin that is not behind HEAD refuses the walk"
  assert_contains "$OUT" "is backward of the pin" "the refusal names the class"
  assert_eq "$(cat "$E_SLOT/rev.git")" "$E_HEAD" "the refused walk left the pin alone"
  bgit "$REPO_E" checkout -q main
else
  say "S8e: SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S8f: the ancestry lattice (forward / backward / diverged)"
# ---------------------------------------------------------------------------
# Ordering is ancestry over the commit graph, never a version string. The
# ceremony classifies the candidate against the pin and refuses anything but
# a forward move unless the human DECLARES the relationship -- and a
# declaration that does not match reality is refused too, naming the class
# that actually holds. Every fixture below builds real ancestry: reset
# --hard for a backward checkout, a branch off an earlier commit for a
# diverged one.
#
# The pre-sudo preview mirrors these refusals, but its elevation gate is
# sed'd to `if false` here -- the same documented gap S8e records. The
# root-side checks are the authoritative half and are all covered.
if [ "$GIT_OK" -eq 1 ]; then
  REPO_G="$FIX/latticefix"
  mkdir -p "$REPO_G"
  bgit "$REPO_G" init -q
  printf 'g0\n' > "$REPO_G/g.txt"
  bgit "$REPO_G" add g.txt; bgit "$REPO_G" commit -q -m "g0 base"
  G_BASE="$(bgit "$REPO_G" rev-parse 'HEAD^{commit}')"
  printf 'G1LINE\n' > "$REPO_G/g1.txt"
  bgit "$REPO_G" add g1.txt; bgit "$REPO_G" commit -q -m "g1 first"
  G_C1="$(bgit "$REPO_G" rev-parse 'HEAD^{commit}')"
  printf 'G2LINE\n' > "$REPO_G/g2.txt"
  bgit "$REPO_G" add g2.txt; bgit "$REPO_G" commit -q -m "g2 second"
  G_C2="$(bgit "$REPO_G" rev-parse 'HEAD^{commit}')"
  # A side line off g1: same repo, different history from g2 on.
  bgit "$REPO_G" checkout -q -b side "$G_C1"
  printf 'GXLINE\n' > "$REPO_G/x.txt"
  bgit "$REPO_G" add x.txt; bgit "$REPO_G" commit -q -m "gx side"
  G_X="$(bgit "$REPO_G" rev-parse 'HEAD^{commit}')"
  bgit "$REPO_G" checkout -q main
  G_SLOT="$(slot_of "$REPO_G")"

  # --- the class itself, straight from the helper ---------------------------
  run_probe_in "$REPO_G" ancestry_class "$REPO_G" "$G_BASE" "$G_C2"
  assert_eq "$POUT" forward "a descendant of the pin is forward"
  run_probe_in "$REPO_G" ancestry_class "$REPO_G" "$G_C2" "$G_BASE"
  assert_eq "$POUT" backward "an ancestor of the pin is backward"
  run_probe_in "$REPO_G" ancestry_class "$REPO_G" "$G_C2" "$G_X"
  assert_eq "$POUT" diverged "a side line is diverged"
  run_probe_in "$REPO_G" ancestry_class "$REPO_G" "$G_C2" "$G_C2"
  assert_eq "$POUT" equal "the same rev is equal"

  # --- forward is untouched: no alarm, the ordinary listing -----------------
  seed_state "$REPO_G" rev.git "$G_BASE"
  ANS='
y
'
  run_pinned review "$REPO_G"
  assert_exit "$RC" 0 "a forward review is unchanged by the lattice"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_C2" "the forward pin moved to HEAD"
  assert_contains "$OUT" "--- commits since last approval ---" "forward keeps the ordinary listing"
  assert_missing "$OUT" "!!!" "a forward move raises no alarm"

  # A declaration on a forward candidate overrides nothing.
  seed_state "$REPO_G" rev.git "$G_BASE"
  ANS=""
  run_pinned review "$REPO_G" --backward
  assert_exit "$RC" 1 "--backward on a forward candidate is refused"
  assert_contains "$OUT" "nothing to override" "the refusal says there is nothing to override"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_BASE" "the refused ceremony left the pin alone"

  # An already-pinned repo short-circuits BEFORE the lattice: equal is a
  # no-op, and a declaration cannot make a no-op into a ceremony.
  seed_state "$REPO_G" rev.git "$G_C2"
  ANS=""
  run_pinned review "$REPO_G" --backward
  assert_exit "$RC" 0 "an equal candidate still short-circuits"
  assert_contains "$OUT" "already pinned" "equal takes the already-pinned path"

  # --- backward: the checkout sits behind its pin ---------------------------
  bgit "$REPO_G" reset --hard -q "$G_C1"
  seed_state "$REPO_G" rev.git "$G_C2"
  ANS='y
'
  run_pinned review "$REPO_G"
  assert_exit "$RC" 1 "an undeclared backward candidate is refused"
  assert_contains "$OUT" "is backward of the pin" "the refusal names the class"
  assert_contains "$OUT" "un-approved" "the refusal says what a backward move does"
  assert_contains "$OUT" "--backward" "the refusal names the flag that declares it"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_C2" "an undeclared backward move records nothing"

  ANS=""
  run_pinned review "$REPO_G" --diverged
  assert_exit "$RC" 1 "a mismatched declaration is refused"
  assert_contains "$OUT" "--diverged declared, but the candidate is backward" \
    "the refusal names the class that actually holds"

  ANS='
y
'
  run_pinned review "$REPO_G" --backward
  assert_exit "$RC" 0 "a declared backward move proceeds"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_C1" "the declared backward move recorded the pin"
  assert_contains "$OUT" "!!! BACKWARD:" "the ceremony raises the backward alarm"
  assert_contains "$OUT" "--- commits being un-approved ---" "the display names the reversed range"
  assert_contains "$OUT" "g2 second" "the un-approved commit is listed"
  assert_contains "$OUT" "--- diff " "the honest diff of the move still runs"

  # A declined backward ceremony is an ordinary decline.
  seed_state "$REPO_G" rev.git "$G_C2"
  ANS='
n
'
  run_pinned review "$REPO_G" --backward
  assert_exit "$RC" 2 "a declined backward ceremony exits 2"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_C2" "the declined ceremony left the pin alone"

  # --- diverged: the checkout left the pinned line --------------------------
  bgit "$REPO_G" reset --hard -q "$G_C2"
  bgit "$REPO_G" checkout -q side
  seed_state "$REPO_G" rev.git "$G_C2"
  ANS='y
'
  run_pinned review "$REPO_G"
  assert_exit "$RC" 1 "an undeclared diverged candidate is refused"
  assert_contains "$OUT" "has diverged from the pin" "the refusal names the class"
  assert_contains "$OUT" "--diverged" "the refusal names the flag that declares it"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_C2" "an undeclared diverged move records nothing"

  ANS=""
  run_pinned review "$REPO_G" --backward
  assert_exit "$RC" 1 "the other mismatched declaration is refused too"
  assert_contains "$OUT" "--backward declared, but the candidate has diverged" \
    "the refusal names the class that actually holds"

  ANS='
y
'
  run_pinned review "$REPO_G" --diverged
  assert_exit "$RC" 0 "a declared diverged move proceeds"
  assert_eq "$(cat "$G_SLOT/rev.git")" "$G_X" "the declared diverged move recorded the pin"
  assert_contains "$OUT" "!!! DIVERGED:" "the ceremony raises the diverged alarm"
  assert_contains "$OUT" "merge base: $G_C1" "the display names the merge base"
  assert_contains "$OUT" "commits being un-approved (leaving the pinned line)" \
    "the display names the abandoned range"
  assert_contains "$OUT" "commits arriving on the new line" "the display names the arriving range"
  assert_contains "$OUT" "g2 second" "the abandoned commit is listed"
  assert_contains "$OUT" "gx side" "the arriving commit is listed"
  bgit "$REPO_G" checkout -q main

  # --- the declarations bind to one repo, and to nothing else ---------------
  seed_state "$REPO_G" rev.git "$G_C2"
  ANS=""
  run_pinned review "$REPO_G" --backward --diverged
  assert_exit "$RC" 1 "two declarations at once are refused"
  assert_contains "$OUT" "declare different relationships" "the refusal names the contradiction"
  ANS=""
  run_pinned review "$REPO_G" --step --backward
  assert_exit "$RC" 1 "a declaration with --step is refused"
  assert_contains "$OUT" "only exist going forward" "the refusal names the walk's direction"
  ANS=""
  run_pinned review "$REPO_G" --trust --backward
  assert_exit "$RC" 1 "a declaration with --trust is refused"
  assert_contains "$OUT" "there is no pin to move --backward from" "the refusal names the vouch"
  ANS=""
  run_pinned review "$REPO_G" "$REPO_A" --backward
  assert_exit "$RC" 1 "a declaration with two repos is refused"
  assert_contains "$OUT" "bind to one repo" "the refusal names the one-repo rule"
  ANS=""
  run_pinned review --file "$SUB/a.conf" --backward
  assert_exit "$RC" 1 "a declaration with --file is refused"
  assert_contains "$OUT" "its own ceremony" "the refusal names the file ceremony"

  # A first approval classifies nothing: there is no pin to move from.
  REPO_I="$FIX/latticefix-new"
  mkdir -p "$REPO_I"
  bgit "$REPO_I" init -q; printf 'i1\n' > "$REPO_I/f"; bgit "$REPO_I" add f
  bgit "$REPO_I" commit -q -m i1
  ANS=""
  run_pinned review "$REPO_I" --diverged
  assert_exit "$RC" 1 "a declaration on a first approval is refused"
  assert_contains "$OUT" "no pin for --diverged to move from" "the refusal names the missing pin"
  assert_absent "$(slot_of "$REPO_I")/rev.git" "the refused first approval recorded nothing"
else
  say "S8f: SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S8g: the signed-release upgrade offer"
# ---------------------------------------------------------------------------
# upgrade meeting a stale repo with a NEWER SIGNED release and an installed
# signer key offers "verify the tag and pin it" instead of a review. The
# thing under test is the SELECTION: candidates are filtered by ancestry,
# then VERIFIED, and only the verified subset is ordered -- so no
# attacker-writable tag name can ever choose what a ceremony covers.
#
# The section needs a signing key, not an agent: git's ssh format signs
# straight from an unencrypted key FILE, so the whole path (sign, discover,
# verify, pin) runs here. Probed rather than assumed -- a git or ssh-keygen
# without SSHSIG skips the section instead of failing it, the GIT_OK /
# REBUILD_TOOL pattern above.
SIGN_OK=0
SIGN_KEY="$FIX/signer.key"
SIGN_KEY2="$FIX/outsider.key"
USER_SIGNERS="$PINNED_ROOT/$USERNAME/policy/allowed_signers"
if [ "$GIT_OK" -eq 1 ] && command -v ssh-keygen >/dev/null 2>&1 \
   && ssh-keygen -t ed25519 -N '' -C pinned-harness -f "$SIGN_KEY" -q >/dev/null 2>&1 \
   && ssh-keygen -t ed25519 -N '' -C pinned-outsider -f "$SIGN_KEY2" -q >/dev/null 2>&1; then
  SIGN_PROBE="$FIX/signprobe"
  mkdir -p "$SIGN_PROBE"
  bgit "$SIGN_PROBE" init -q
  printf 'p\n' > "$SIGN_PROBE/f"; bgit "$SIGN_PROBE" add f
  bgit "$SIGN_PROBE" commit -q -m p
  printf 'harness namespaces="git" %s\n' "$(cat "$SIGN_KEY.pub")" > "$FIX/allowed.probe"
  if bgit "$SIGN_PROBE" -c gpg.format=ssh -c user.signingkey="$SIGN_KEY" \
       tag -s probe -m probe >/dev/null 2>&1 \
     && bgit "$SIGN_PROBE" -c gpg.ssh.allowedSignersFile="$FIX/allowed.probe" \
       verify-tag probe >/dev/null 2>&1; then
    SIGN_OK=1
  fi
fi

sign_tag() { # repo tag [commit] -- an ordinary `git tag -s`, ssh format
  local r="$1" t="$2"; shift 2
  bgit "$r" -c gpg.format=ssh -c user.signingkey="$SIGN_KEY" \
    tag -s "$t" -m "release $t" "$@"
}
sign_tag_outsider() { # repo tag [commit] -- signed by a key nobody installed
  local r="$1" t="$2"; shift 2
  bgit "$r" -c gpg.format=ssh -c user.signingkey="$SIGN_KEY2" \
    tag -s "$t" -m "release $t" "$@"
}
seed_signers_user() { # pubkey-file -- as the signer ceremony would record it
  mkdir -p "$(dirname "$USER_SIGNERS")"
  printf 'harness namespaces="git" %s\n' "$(cat "$1")" > "$USER_SIGNERS"
  chmod 640 "$USER_SIGNERS"
}

if [ "$GIT_OK" -eq 1 ] && [ -x "$REBUILD_TOOL" ] && [ "$SIGN_OK" -eq 1 ]; then
  # REPO_S, rev-only slot, linear history:
  #   s1 <- the pin
  #   s2   tag v1        signed by the installed key
  #   s3   tags v2, v2-vendor -- both signed by the installed key
  #   s4   HEAD; tag v3-evil signed by an OUTSIDER, tag v4-plain unsigned
  # The maximum of the VERIFIED set is s3, so v2 and v2-vendor are the offer;
  # the newer names at HEAD carry no signature this machine trusts and never
  # enter the selection at all.
  REPO_S="$FIX/signfix"
  mkdir -p "$REPO_S"
  bgit "$REPO_S" init -q
  printf 's1\n' > "$REPO_S/f"; bgit "$REPO_S" add f; bgit "$REPO_S" commit -q -m s1
  S_PIN="$(bgit "$REPO_S" rev-parse 'HEAD^{commit}')"
  printf 's2\n' > "$REPO_S/f"; bgit "$REPO_S" commit -q -am s2
  sign_tag "$REPO_S" v1
  printf 's3\n' > "$REPO_S/f"; bgit "$REPO_S" commit -q -am s3
  S_REL="$(bgit "$REPO_S" rev-parse 'HEAD^{commit}')"
  sign_tag "$REPO_S" v2
  sign_tag "$REPO_S" v2-vendor
  printf 's4\n' > "$REPO_S/f"; bgit "$REPO_S" commit -q -am s4
  sign_tag_outsider "$REPO_S" v3-evil
  bgit "$REPO_S" tag v4-plain
  S_SLOT="$(slot_of "$REPO_S")"
  seed_state "$REPO_S" rev.git "$S_PIN"

  # REPO_T, TAG-DECLARED slot: the offer covers these too, and outranks the
  # head_release_tag rule. HEAD carries no release, so without the offer this
  # repo would be routed to a by-hand `review --tag`.
  REPO_T="$FIX/signfix-tagged"
  mkdir -p "$REPO_T"
  bgit "$REPO_T" init -q
  printf 't1\n' > "$REPO_T/f"; bgit "$REPO_T" add f; bgit "$REPO_T" commit -q -m t1
  T_PIN="$(bgit "$REPO_T" rev-parse 'HEAD^{commit}')"
  bgit "$REPO_T" tag t1
  printf 't2\n' > "$REPO_T/f"; bgit "$REPO_T" commit -q -am t2
  T_REL="$(bgit "$REPO_T" rev-parse 'HEAD^{commit}')"
  sign_tag "$REPO_T" t2
  printf 't3\n' > "$REPO_T/f"; bgit "$REPO_T" commit -q -am t3
  T_SLOT="$(slot_of "$REPO_T")"
  seed_state "$REPO_T" rev.git "$T_PIN"
  seed_state "$REPO_T" tag t1

  cat > "$FIX/flake-signed.nix" <<EOF
{
  inputs.signfix.url = "git+file://$REPO_S?rev=$S_PIN";
  inputs.signfix-tagged.url = "git+file://$REPO_T?rev=$T_PIN";
}
EOF

  # No installed signer key: no offer at all, silently -- the repos take
  # their ordinary routes (plain review; by-hand --tag for the declared one).
  ANS=""
  run_pinned upgrade --flake "$FIX/flake-signed.nix" --dry-run
  assert_exit "$RC" 0 "the plan without a signers file exits 0"
  assert_missing "$OUT" "signed release" "no signers file means no offer"
  assert_contains "$OUT" "no single release tag at HEAD" \
    "and the tag-declared repo falls back to by-hand approval"

  seed_signers_user "$SIGN_KEY.pub"

  # With the key installed the plan routes both repos to the signature gate,
  # and says which release -- not which HEAD -- is about to be pinned.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake-signed.nix" --dry-run
  assert_exit "$RC" 0 "the plan with a signers file exits 0"
  assert_contains "$OUT" "(signed release v2, v2-vendor -- signature-gated)" \
    "both tags naming the maximum verified commit ride along"
  assert_contains "$OUT" "HEAD is 1 commit past the release" \
    "the orientation names the gap between HEAD and the release"
  assert_missing "$OUT" "v3-evil" "a tag signed by an uninstalled key is not a candidate"
  assert_missing "$OUT" "v4-plain" "an unsigned tag at HEAD is not a candidate"
  assert_contains "$OUT" "(signed release t2 -- signature-gated)" \
    "the offer outranks the tag-declared route"
  assert_missing "$OUT" "no single release tag at HEAD" \
    "so the by-hand tag skip no longer applies to it"
  assert_eq "$(cat "$S_SLOT/rev.git")" "$S_PIN" "the plan records nothing"

  # The ceremony IS review --signed-tag: its y/N is the offer's acceptance.
  ANS='y
y
'
  run_pinned upgrade --flake "$FIX/flake-signed.nix"
  assert_exit "$RC" 2 "the signed upgrade reaches deploy's confirmation gate"
  assert_contains "$OUT" "signature verified against $USER_SIGNERS" \
    "the ceremony verified against the root-owned signers file"
  assert_contains "$OUT" "2/2 tags agree on the commit below" \
    "the agreeing tags are read as k-of-n agreement"
  assert_eq "$(cat "$S_SLOT/rev.git")" "$S_REL" "the RELEASE is pinned, not HEAD"
  assert_eq "$(cat "$S_SLOT/tag")" "v2" "the declaration landed in the slot"
  assert_eq "$(cat "$T_SLOT/rev.git")" "$T_REL" "the tag-declared repo pinned at its signed release"
  assert_eq "$(cat "$T_SLOT/tag")" "t2" "and its declaration followed the release"

  # Nothing verified remains above the new pin: the only newer names are the
  # outsider's signature and a bare name, so the repo drops back to its
  # ordinary route rather than being offered anything.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake-signed.nix" --dry-run
  assert_exit "$RC" 0 "the follow-up plan exits 0"
  assert_missing "$OUT" "signed release" "no verified tag above the pin means no offer"
  assert_contains "$OUT" "no single release tag at HEAD" \
    "the tag-declared slot is back to by-hand approval"

  # A decline is the offer's refusal: the batch contract skips this repo.
  bgit "$REPO_S" tag -d v3-evil >/dev/null
  bgit "$REPO_S" tag -d v4-plain >/dev/null
  sign_tag "$REPO_S" v5
  ANS='n
'
  run_pinned upgrade --flake "$FIX/flake-signed.nix"
  assert_exit "$RC" 2 "declining the offer still reaches deploy"
  assert_contains "$OUT" "(signed release v5 -- signature-gated)" "the new release is offered"
  assert_contains "$OUT" "0 approved, 1 declined" "the decline skipped the repo"
  assert_eq "$(cat "$S_SLOT/rev.git")" "$S_REL" "a declined offer moves no pin"

  # VERIFIED TAGS THAT DO NOT ORDER: two signed releases on branches that
  # merge into HEAD. Both descend from the pin and both are ancestors of
  # HEAD, but neither contains the other -- there is no maximum to offer, so
  # nothing here may choose one. Named loudly, never automatic.
  REPO_D2="$FIX/signfix-split"
  mkdir -p "$REPO_D2"
  bgit "$REPO_D2" init -q
  printf 'd0\n' > "$REPO_D2/f"; bgit "$REPO_D2" add f; bgit "$REPO_D2" commit -q -m d0
  D2_PIN="$(bgit "$REPO_D2" rev-parse 'HEAD^{commit}')"
  bgit "$REPO_D2" checkout -q -b sa
  printf 'da\n' > "$REPO_D2/a"; bgit "$REPO_D2" add a; bgit "$REPO_D2" commit -q -m da
  sign_tag "$REPO_D2" rel-a
  bgit "$REPO_D2" checkout -q main
  bgit "$REPO_D2" checkout -q -b sb
  printf 'db\n' > "$REPO_D2/b"; bgit "$REPO_D2" add b; bgit "$REPO_D2" commit -q -m db
  sign_tag "$REPO_D2" rel-b
  bgit "$REPO_D2" checkout -q main
  bgit "$REPO_D2" merge -q --no-ff -m ma sa
  bgit "$REPO_D2" merge -q --no-ff -m mb sb
  seed_state "$REPO_D2" rev.git "$D2_PIN"
  cat > "$FIX/flake-split.nix" <<EOF
{
  inputs.signfix-split.url = "git+file://$REPO_D2?rev=$D2_PIN";
}
EOF
  ANS=""
  run_pinned upgrade --flake "$FIX/flake-split.nix" --dry-run
  assert_exit "$RC" 0 "a plan with disagreeing verified tags exits 0"
  assert_contains "$OUT" "verified signed tags disagree -- review --signed-tag by hand" \
    "no unique maximum is a loud skip"
  assert_no_row "$OUT" "review:" "$REPO_D2" "and the repo joins no batch"
  ANS='y
'
  run_pinned upgrade --flake "$FIX/flake-split.nix"
  assert_exit "$RC" 2 "the run reaches deploy without a ceremony"
  assert_eq "$(cat "$(slot_of "$REPO_D2")/rev.git")" "$D2_PIN" "the pin is untouched"

  # A signed release BEHIND the pin is not a candidate: strictly-descends is
  # part of the filter, so a replayed older release cannot be offered. (The
  # ancestry floor in the ceremony would catch it too; this keeps it out of
  # the selection in the first place.)
  REPO_O="$FIX/signfix-old"
  mkdir -p "$REPO_O"
  bgit "$REPO_O" init -q
  printf 'o1\n' > "$REPO_O/f"; bgit "$REPO_O" add f; bgit "$REPO_O" commit -q -m o1
  sign_tag "$REPO_O" old1
  printf 'o2\n' > "$REPO_O/f"; bgit "$REPO_O" commit -q -am o2
  O_PIN="$(bgit "$REPO_O" rev-parse 'HEAD^{commit}')"
  printf 'o3\n' > "$REPO_O/f"; bgit "$REPO_O" commit -q -am o3
  seed_state "$REPO_O" rev.git "$O_PIN"
  cat > "$FIX/flake-old.nix" <<EOF
{
  inputs.signfix-old.url = "git+file://$REPO_O?rev=$O_PIN";
}
EOF
  ANS=""
  run_pinned upgrade --flake "$FIX/flake-old.nix" --dry-run
  assert_exit "$RC" 0 "a plan whose only signed tag is behind the pin exits 0"
  assert_missing "$OUT" "signed release" "a signed release behind the pin is no candidate"
  assert_row "$OUT" "review:" "$REPO_O" "the repo takes the ordinary review route"

  # A signed release on a SIDE branch is not a candidate either: upgrade
  # follows the checkout's own line, and a release the checkout has not
  # merged is by-hand work.
  bgit "$REPO_O" checkout -q -b aside "$O_PIN"
  printf 'ox\n' > "$REPO_O/f"; bgit "$REPO_O" commit -q -am ox
  sign_tag "$REPO_O" side1
  bgit "$REPO_O" checkout -q main
  ANS=""
  run_pinned upgrade --flake "$FIX/flake-old.nix" --dry-run
  assert_exit "$RC" 0 "a plan with a side-branch release exits 0"
  assert_missing "$OUT" "signed release" "a release off the checkout's line is no candidate"
  assert_missing "$OUT" "verified signed tags disagree" \
    "and it is filtered out before it can look like a disagreement"

  rm -f "$USER_SIGNERS"
else
  say "S8g: SKIPPED (no git fixture, no rebuild tool, or no ssh signing)"
fi

# ---------------------------------------------------------------------------
say "S8h: the pre-sudo upgrade preview, and deploy's confirm"
# ---------------------------------------------------------------------------
# The only section driven by the PREVIEW stub, where the elevation gate is
# live: these are the lines a human meets BEFORE authenticating. `exit 97`
# stands in for the sudo that would follow, so "would have elevated" and
# "exited first" are two different exit codes.
if [ "$GIT_OK" -eq 1 ]; then
  PV_PIN="$FIX/pv-pin"; PV_S1="$FIX/pv-stale1"; PV_S2="$FIX/pv-stale2"
  PV_NS="$FIX/pv-noslot"
  mkdir -p "$PV_PIN" "$PV_S1" "$PV_S2" "$PV_NS"
  for ur in "$PV_PIN" "$PV_S1" "$PV_S2" "$PV_NS"; do
    bgit "$ur" init -q
    printf 'p1\n' > "$ur/f"; bgit "$ur" add f; bgit "$ur" commit -q -m p1
  done
  PV_PIN_REV="$(bgit "$PV_PIN" rev-parse 'HEAD^{commit}')"
  PV_S1_REV="$(bgit "$PV_S1" rev-parse 'HEAD^{commit}')"
  PV_S2_REV="$(bgit "$PV_S2" rev-parse 'HEAD^{commit}')"
  PV_NS_REV="$(bgit "$PV_NS" rev-parse 'HEAD^{commit}')"
  printf 'p2\n' > "$PV_S1/f"; bgit "$PV_S1" commit -q -am p2
  printf 'p2\n' > "$PV_S2/f"; bgit "$PV_S2" commit -q -am p2
  seed_state "$PV_PIN" rev.git "$PV_PIN_REV"
  seed_state "$PV_S1" rev.git "$PV_S1_REV"
  seed_state "$PV_S2" rev.git "$PV_S2_REV"
  cat > "$FIX/flake-pv-quiet.nix" <<EOF
{
  inputs.pv-pin.url = "git+file://$PV_PIN?rev=$PV_PIN_REV";
}
EOF
  cat > "$FIX/flake-pv-one.nix" <<EOF
{
  inputs.pv-pin.url = "git+file://$PV_PIN?rev=$PV_PIN_REV";
  inputs.pv-stale1.url = "git+file://$PV_S1?rev=$PV_S1_REV";
}
EOF
  cat > "$FIX/flake-pv-two.nix" <<EOF
{
  inputs.pv-stale1.url = "git+file://$PV_S1?rev=$PV_S1_REV";
  inputs.pv-stale2.url = "git+file://$PV_S2?rev=$PV_S2_REV";
}
EOF
  cat > "$FIX/flake-pv-unpinned.nix" <<EOF
{
  inputs.pv-pin.url = "git+file://$PV_PIN?rev=$PV_PIN_REV";
  inputs.pv-noslot.url = "git+file://$PV_NS?rev=$PV_NS_REV";
}
EOF

  # Nothing actionable: the round is over before it costs an authentication,
  # and the hint names the verb that still rebuilds.
  ANS=""
  run_preview upgrade --flake "$FIX/flake-pv-quiet.nix"
  assert_exit "$RC" 0 "an empty round exits 0 without reaching sudo"
  assert_contains "$OUT" "nothing to approve" "the plan says so"
  assert_contains "$OUT" "To rebuild anyway:" "and the hint follows it"
  assert_contains "$OUT" "pinned deploy" "naming the verb that rebuilds"
  assert_missing "$OUT" "Then: deploy" "the old chained-plan line is gone"
  assert_missing "$OUT" "Will run as root:" "no elevation is displayed"
  assert_missing "$OUT" "Enter continues" "and no gate is offered"

  # --yes and --dry-run buy nothing here: an empty round needs no root either
  # way, so both take the same exit.
  ANS=""
  run_preview upgrade --flake "$FIX/flake-pv-quiet.nix" --yes
  assert_exit "$RC" 0 "--yes does not authenticate an empty round"
  assert_contains "$OUT" "To rebuild anyway:" "the hint prints under --yes too"
  ANS=""
  run_preview upgrade --flake "$FIX/flake-pv-quiet.nix" --dry-run
  assert_exit "$RC" 0 "--dry-run exits before sudo as well"
  assert_contains "$OUT" "To rebuild anyway:" "with the same hint"

  # One stale input: the gate counts the round, the disclaimer stays, and an
  # Enter reaches the elevation.
  ANS='
'
  run_preview upgrade --flake "$FIX/flake-pv-one.nix"
  assert_exit "$RC" 97 "an answered gate reaches the elevation"
  assert_contains "$OUT" "next: review 1 repo + rebuild as root (sudo); Enter continues" \
    "the gate counts the round in the singular"
  assert_contains "$OUT" "Ctrl-C stops" "and names the way out"
  assert_contains "$OUT" "The preview above was orientation only." \
    "the orientation disclaimer stays"
  assert_missing "$OUT" "Will run as root:" "upgrade displays no command line pre-sudo"
  assert_missing "$OUT" "To rebuild anyway:" "and no no-op hint on the stale path"

  # Two of them: plural_s, and the count is the plan's own review rows.
  ANS='
'
  run_preview upgrade --flake "$FIX/flake-pv-two.nix"
  assert_exit "$RC" 97 "the two-repo round reaches the elevation"
  assert_contains "$OUT" "next: review 2 repos + rebuild as root (sudo)" \
    "the gate counts both repos"

  # --yes answers the gate at the command line.
  ANS=""
  run_preview upgrade --flake "$FIX/flake-pv-one.nix" --yes
  assert_exit "$RC" 97 "--yes elevates without a gate"
  assert_missing "$OUT" "Enter continues" "no gate is printed under --yes"

  # Off-tty the gate cannot be answered: refuse rather than elevate unasked.
  NOTTY=1
  ANS=""
  run_preview upgrade --flake "$FIX/flake-pv-one.nix"
  assert_exit "$RC" 2 "off-tty without --yes refuses"
  assert_contains "$OUT" "no tty for confirmation -- pass --yes to proceed non-interactively" \
    "the refusal names the flag that proceeds"
  ANS=""
  run_preview upgrade --flake "$FIX/flake-pv-one.nix" --yes
  assert_exit "$RC" 97 "off-tty WITH --yes still elevates"
  NOTTY=""

  if [ -x "$REBUILD_TOOL" ]; then
    # deploy's own gate, reachable here because the preview stub seams its
    # no-tty refusal: the confirm asks for the act it performs.
    ANS='n
'
    run_preview deploy --flake "$FIX/flake-pv-quiet.nix"
    assert_exit "$RC" 2 "declining deploy's confirm exits 2"
    assert_contains "$OUT" "rebuild? [y/N]" "the confirm names what a yes does"
    assert_missing "$OUT" "proceed? [y/N]" "the old wording is gone"
    assert_contains "$OUT" "all inputs at their approved revs" "the verdict is a label, not a sentence"
    assert_contains "$OUT" "(converges the running system to the flake -- changes nothing if already current)" \
      "the unconditional rebuild carries its reason on the command"
    assert_missing "$OUT" "Rebuilding anyway" "the paragraph that used to carry it is gone"
    assert_contains "$OUT" "sudo $REBUILD_TOOL switch --flake" \
      "an unprivileged deploy rebuilds under sudo"

    ANS=""
    run_preview deploy --flake "$FIX/flake-pv-unpinned.nix" --dry-run
    assert_exit "$RC" 0 "a dry run with an unpinned input exits 0"
    assert_contains "$OUT" "pinned inputs all at their approved revs" \
      "the mixed verdict is lowercase too"

    # The root context (what `pinned upgrade` reaches): sudo is an admitted
    # no-op there, so it leaves the displayed command and the argv together.
    TESTROOT=1
    ANS='n
'
    run_preview deploy --flake "$FIX/flake-pv-quiet.nix"
    assert_exit "$RC" 2 "the root-context deploy still confirms"
    assert_contains "$OUT" "Will run as root:" "the label stays in the root context"
    assert_contains "$OUT" "$REBUILD_TOOL switch --flake" "the rebuild command is unchanged"
    assert_missing "$OUT" "sudo $REBUILD_TOOL" "but sudo is dropped from the displayed line"
    TESTROOT=""
  fi
else
  say "S8h: SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S8i: the pre-sudo elevation display and its gate"
# ---------------------------------------------------------------------------
# The rest of the PREVIEW stub's territory: what review, add, signer and
# ignorable put on screen before sudo is asked for anything.
#
# THE COMMAND LINE IS THE ASSERTION THAT MATTERS. The prose header over it is
# gone (the argv already opens with `sudo` and the gate already says "as root
# (sudo)" -- three statements of one fact), but on a host without sudowhat
# nothing root-side reprints the argv before the authentication sheet, so the
# line itself is the only pre-auth disclosure there is. Its disappearance
# would be a silent loss, which is why every path below asserts BOTH halves:
# no header, and the exact `sudo -- ...` line still on the page.
#
# The gate's own newline is the user's Enter echo, which a file-backed stdin
# never produces -- so the separator blank the script prints after the read
# is what terminates the gate line here.
if [ "$GIT_OK" -eq 1 ]; then
  EV_STALE="$FIX/ev-stale"; EV_STALE2="$FIX/ev-stale2"; EV_PINNED="$FIX/ev-pinned"
  EV_ADD="$FIX/ev-add"; EV_ADDPIN="$FIX/ev-addpin"
  for ur in "$EV_STALE" "$EV_STALE2" "$EV_PINNED" "$EV_ADD" "$EV_ADDPIN"; do
    mkdir -p "$ur"
    bgit "$ur" init -q
    printf 'e1\n' > "$ur/f"; bgit "$ur" add f; bgit "$ur" commit -q -m e1
  done
  # Pinned at the commit they are on; the two stale ones then move past it.
  seed_state "$EV_STALE"  rev.git "$(bgit "$EV_STALE"  rev-parse 'HEAD^{commit}')"
  seed_state "$EV_STALE2" rev.git "$(bgit "$EV_STALE2" rev-parse 'HEAD^{commit}')"
  seed_state "$EV_PINNED" rev.git "$(bgit "$EV_PINNED" rev-parse 'HEAD^{commit}')"
  seed_state "$EV_ADDPIN" rev.git "$(bgit "$EV_ADDPIN" rev-parse 'HEAD^{commit}')"
  printf 'e2\n' > "$EV_STALE/f";  bgit "$EV_STALE"  commit -q -am e2
  printf 'e2\n' > "$EV_STALE2/f"; bgit "$EV_STALE2" commit -q -am e2
  EV_FLAKE="$FIX/flake-ev.nix"
  printf '{ inputs = { }; }\n' > "$EV_FLAKE"

  # --- review <repo> --------------------------------------------------------
  ANS='
'
  run_preview review "$EV_STALE"
  assert_exit "$RC" 97 "an answered review gate reaches the elevation"
  assert_missing "$OUT" "Will run as root:" "review prints no prose header"
  assert_contains "$OUT" "sudo -- $PREVIEW review $EV_STALE" \
    "the exact argv stays on screen -- it is the only pre-auth disclosure"
  assert_contains "$OUT" "next: review 1 repo as root (sudo); Enter continues" \
    "the gate counts the repo in the singular"
  assert_contains "$OUT" "Ctrl-C stops" "and names the way out"
  assert_contains "$OUT" "The preview above was orientation only." \
    "the orientation disclaimer stays"
  assert_before "$OUT" "The preview above was orientation only." "sudo -- $PREVIEW" \
    "the contract sentence sits above the command it describes"
  assert_before "$OUT" "sudo -- $PREVIEW" "next: review 1 repo" \
    "and the gate comes last, after the command has been read"

  ANS='
'
  run_preview review "$EV_STALE" "$EV_STALE2"
  assert_exit "$RC" 97 "the two-repo review reaches the elevation"
  assert_contains "$OUT" "next: review 2 repos as root (sudo)" "the gate counts both repos"

  # The gate counts the ROUND, not the argv: a repo already at its pin was
  # skipped by the preview and buys no ceremony, so promising it would be a
  # count the root side then contradicts.
  ANS='
'
  run_preview review "$EV_PINNED" "$EV_STALE"
  assert_exit "$RC" 97 "a mixed batch still elevates for the stale repo"
  assert_contains "$OUT" "already pinned:" "the preview skips the pinned one"
  assert_contains "$OUT" "next: review 1 repo as root (sudo)" \
    "and the gate counts only what the root side will review"

  # --yes answers the gate at the command line -- and rides through in the
  # displayed argv, because the display IS the argv sudo gets.
  ANS=""
  run_preview review "$EV_STALE" --yes
  assert_exit "$RC" 97 "--yes elevates review without a gate"
  assert_missing "$OUT" "Enter continues" "no gate is printed under --yes"
  assert_contains "$OUT" "sudo -- $PREVIEW review $EV_STALE --yes" \
    "the flag is shown where it will really be passed"

  # Off-tty there is nobody to answer: refuse rather than elevate unasked.
  NOTTY=1
  ANS=""
  run_preview review "$EV_STALE"
  assert_exit "$RC" 2 "off-tty review without --yes refuses"
  assert_contains "$OUT" "no tty for confirmation -- pass --yes to proceed non-interactively" \
    "the refusal names the flag that proceeds"
  ANS=""
  run_preview review "$EV_STALE" --yes
  assert_exit "$RC" 97 "off-tty WITH --yes still elevates"
  NOTTY=""

  # --- review --file --------------------------------------------------------
  # No preview of its own, so no contract sentence either: the launcher that
  # measured the files owns that line.
  ANS='
'
  run_preview review --file "$SUB/real.txt"
  assert_exit "$RC" 97 "an answered --file gate reaches the elevation"
  assert_missing "$OUT" "Will run as root:" "review --file prints no prose header"
  assert_contains "$OUT" "sudo -- $PREVIEW review --file $SUB/real.txt" \
    "the file ceremony's argv stays on screen"
  assert_contains "$OUT" "next: review 1 file as root (sudo); Enter continues" \
    "the gate counts the file in the singular"
  assert_missing "$OUT" "The preview above was orientation only." \
    "and claims no preview it did not print"

  ANS='
'
  run_preview review --file "$SUB/real.txt" --file "$SUB/link.txt"
  assert_exit "$RC" 97 "two files reach the elevation too"
  assert_contains "$OUT" "next: review 2 files as root (sudo)" "the gate counts both files"

  # --- add ------------------------------------------------------------------
  ANS='
'
  run_preview add "$EV_ADD" --flake "$EV_FLAKE"
  assert_exit "$RC" 97 "an answered add gate reaches the elevation"
  assert_missing "$OUT" "Will run as root:" "add prints no prose header"
  assert_contains "$OUT" "sudo -- $PREVIEW add $EV_ADD --flake $EV_FLAKE" \
    "add's argv stays on screen"
  assert_contains "$OUT" "next: approve ev-add + edit the flake as root (sudo); Enter continues" \
    "the gate names the input the ceremony will approve"

  # Already pinned: the round is the flake edit alone, and the gate says so
  # rather than promising a review that will not happen.
  ANS='
'
  run_preview add "$EV_ADDPIN" --flake "$EV_FLAKE"
  assert_exit "$RC" 97 "an already-pinned checkout still elevates for the flake edit"
  assert_contains "$OUT" "next: edit the flake as root (sudo); Enter continues" \
    "the gate promises only the edit"
  assert_missing "$OUT" "next: approve" "and no approval it will not perform"

  # --- signer / ignorable ---------------------------------------------------
  ANS='
'
  run_preview signer add alice --file "$SUB/alice.pub"
  assert_exit "$RC" 97 "an answered signer gate reaches the elevation"
  assert_missing "$OUT" "Will run as root:" "signer prints no prose header"
  assert_contains "$OUT" "sudo -- $PREVIEW signer add alice --file $SUB/alice.pub" \
    "signer's argv stays on screen"
  assert_contains "$OUT" "next: record the key as root (sudo); Enter continues" \
    "the gate names what root does with the key"
  assert_contains "$OUT" "sudo asks you to authenticate" "the site's contract line survives"
  assert_before "$OUT" "sudo asks you to authenticate" "sudo -- $PREVIEW signer" \
    "the contract sentence sits above the command"
  assert_before "$OUT" "sudo -- $PREVIEW signer" "next: record the key" \
    "and the gate comes last here too"

  ANS='
'
  run_preview signer remove alice --file "$SUB/alice.pub"
  assert_exit "$RC" 97 "signer remove reaches the elevation"
  assert_contains "$OUT" "next: remove the key as root (sudo)" "its gate names the withdrawal"

  ANS='
'
  run_preview ignorable add model
  assert_exit "$RC" 97 "an answered ignorable gate reaches the elevation"
  assert_missing "$OUT" "Will run as root:" "ignorable prints no prose header"
  assert_contains "$OUT" "sudo -- $PREVIEW ignorable add model" "ignorable's argv stays on screen"
  assert_contains "$OUT" "next: record the grant as root (sudo); Enter continues" \
    "the gate names what root does with the grant"

  ANS='
'
  run_preview ignorable remove model
  assert_exit "$RC" 97 "ignorable remove reaches the elevation"
  assert_contains "$OUT" "next: withdraw the grant as root (sudo)" \
    "its gate names the withdrawal in the grant's own words"

  NOTTY=1
  ANS=""
  run_preview signer add alice --file "$SUB/alice.pub"
  assert_exit "$RC" 2 "off-tty signer without --yes refuses"
  assert_contains "$OUT" "no tty for confirmation -- pass --yes to proceed non-interactively" \
    "with the same refusal every gate uses"
  ANS=""
  run_preview ignorable add model --yes
  assert_exit "$RC" 97 "off-tty ignorable WITH --yes elevates"
  assert_missing "$OUT" "Enter continues" "and prints no gate"
  NOTTY=""

  # --- the root side accepts the answer it was handed -----------------------
  # The gate's --yes rides through in "$@" (the display IS the argv), so every
  # root-side parser must take it as the no-op it is. A parser that did not
  # would turn the documented non-interactive path into a usage error AFTER
  # the authentication.
  ANS='
y
'
  run_pinned review "$EV_STALE2" --yes
  assert_exit "$RC" 0 "the root side reviews with --yes in its argv"
  assert_missing "$OUT" "usage: pinned" "--yes is not a usage error there"
  assert_eq "$(cat "$(slot_of "$EV_STALE2")/rev.git")" \
            "$(bgit "$EV_STALE2" rev-parse 'HEAD^{commit}')" \
            "and the ceremony still wrote the pin it was asked for"

  if command -v ssh-keygen >/dev/null 2>&1; then
    # Far enough into do_signer to prove the option parser took --yes: the
    # refusal below comes from the key file, not from the grammar.
    ANS=""
    run_pinned signer add --file "$FIX/no-such-key.pub" --yes
    assert_exit "$RC" 1 "signer with --yes reaches its own checks"
    assert_contains "$OUT" "not a readable file" "and fails on the key, not on the flag"
    assert_missing "$OUT" "unknown signer option" "--yes is not an unknown option"
  else
    say "S8i: SKIPPED signer --yes (no ssh-keygen)"
  fi

  if command -v jq >/dev/null 2>&1; then
    ANS=""
    run_pinned ignorable add 'bad!key' --yes
    assert_exit "$RC" 1 "ignorable with --yes reaches its own checks"
    assert_contains "$OUT" "outside the key grammar" "and fails on the key, not on the flag"
    assert_missing "$OUT" "unknown ignorable option" "--yes is not an unknown option"
  else
    say "S8i: SKIPPED ignorable --yes (no jq)"
  fi
else
  say "S8i: SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S9: ignored keys (ignored.json / approved / exit 5)"
# ---------------------------------------------------------------------------
# The tolerance path is jq-driven by construction (structural comparison of
# two JSON documents), so without jq there is nothing to exercise -- the
# no-jq behaviour itself is the loud fallback tested at the end of S9.
if ! command -v jq >/dev/null 2>&1; then
  say "S9: SKIPPED (no jq in the trusted PATH)"
else
mkdir -p "$SUB/ig"

# A ceremony may only declare what the ignorable policy grants, so S9 opens
# by granting its keys everywhere; the SCOPING and the tiers are S10's
# subject. No machine tier here: absent means no machine constraint.
seed_policy_user '[{"path":["model"]},{"path":["effortLevel"]},{"path":["statusLine","command"]}]'

# The declaration is recorded ONLY by the ceremony, as the JSON array of key
# paths jq's delpaths wants. Custody is a SEPARATE decision: this slot
# declares ignored keys and keeps no witness of its own, so the comparison it
# enables needs one from the caller.
printf '{\n  "model": "opus",\n  "effortLevel": "high",\n  "permissions": {"deny": ["Bash"]}\n}\n' > "$SUB/ig/nocopy.json"
ANS='
y
'
run_pinned review --file "$SUB/ig/nocopy.json" --ignore-json-key model --ignore-json-key effortLevel
assert_exit "$RC" 0 "review with --ignore-json-key succeeds"
assert_contains "$OUT" "ignored:" "ceremony displays the proposed ignored keys"
assert_contains "$OUT" "model, effortLevel" "ceremony names them before the confirm"
assert_contains "$OUT" "may drift without re-approval" "ceremony states what ignoring means"
assert_contains "$OUT" "granted by user policy, everywhere: model, effortLevel" \
                "ceremony shows the keys' grant provenance on one line"
assert_contains "$OUT" "No copy is kept at rest" "ceremony states the custody consequence"
assert_file "$(slot_file_of "$SUB/ig/nocopy.json" ignored.json)" "ignored.json recorded"
assert_eq "$(cat "$(slot_file_of "$SUB/ig/nocopy.json" ignored.json)")" '[["model"],["effortLevel"]]' \
          "ignored.json holds the jq path array, in declaration order"
assert_absent "$(slot_file_of "$SUB/ig/nocopy.json" approved)" \
              "a declaration alone keeps no witness -- custody is opt-in"

# --store is what keeps the bytes, and it keeps exactly the approved ones.
printf '{\n  "model": "opus",\n  "effortLevel": "high",\n  "permissions": {"deny": ["Bash"]}\n}\n' > "$SUB/ig/copy.json"
COPY_SLOT="$(slot_of "$SUB/ig/copy.json")"
ANS='
y
'
run_pinned review --file "$SUB/ig/copy.json" --ignore-json-key model --store
assert_exit "$RC" 0 "review with a declaration AND --store succeeds"
assert_file "$COPY_SLOT/approved" "--store keeps the approved bytes"
assert_contains "$OUT" "(+approved copy)" "the ceremony says the copy was written"
assert_contains "$OUT" "kept in the slot" "the ceremony states the custody consequence"
assert_eq "$(digest_of "$COPY_SLOT/approved")" "$(awk '{print $1}' "$COPY_SLOT/pin.sha256")" \
          "the copy re-hashes to the pin beside it"
if cmp -s "$COPY_SLOT/approved" "$SUB/ig/copy.json"; then
  ok "the stored copy is byte-identical to what was approved"
else
  fail "the stored copy differs from the approved file"
fi
run_pinned verify "$SUB/ig/copy.json"
assert_exit "$RC" 0 "an unchanged file with a copy still verifies byte-exact"

# The pin stays byte-exact: `shasum -c` must keep working on a slot that
# declares ignored keys.
if (cd / && shasum -a 256 -c "$COPY_SLOT/pin.sha256" >/dev/null 2>&1); then
  ok "shasum -c still verifies the pin of an ignore-declaring slot"
else
  fail "shasum -c cross-check broke on an ignore-declaring slot"
fi

# REGRESSION: a slot that declares ignored keys AND holds a copy states both,
# each as its own field under the same path -- the entry's indentation is what
# binds them, so neither fact has to ride the other's line to be readable.
# Its copy-less sibling in the same directory takes the other branch, so one
# --under run covers both.
run_pinned list --under "$SUB/ig"
assert_exit "$RC" 0 "list exits 0 over the ignore-declaring fixtures"
assert_contains "$OUT" "ignored:  model" "the declaration is its own field"
assert_contains "$OUT" "custody:  kept in the slot" "custody is its own field beside it"
assert_contains "$OUT" "custody:  none" \
                "a declaring slot without a copy still says custody is missing"
assert_eq "$(grep -c '^  custody:' "$OUT" || true)" "$(grep -cE '^[^ ]' "$OUT" || true)" \
          "every entry states custody exactly once, declaration or not"

# Exit 5 via the slot's own copy, naming the key that actually moved.
printf '{\n  "model": "sonnet",\n  "effortLevel": "high",\n  "permissions": {"deny": ["Bash"]}\n}\n' > "$SUB/ig/copy.json"
run_pinned verify "$SUB/ig/copy.json"
assert_exit "$RC" 5 "drift confined to an ignored key -> 5"
assert_contains "$OUT" "ignored-drift: model" "5 names the drifted key on stdout"
assert_missing  "$OUT" "ignored-drift: effortLevel" "an unchanged declared key is not reported"

# --emit is byte-exact only: it must never hand a parser unapproved bytes.
run_pinned verify --emit "$SUB/ig/copy.json"
assert_exit "$RC" 11 "--emit never answers 5"
assert_missing "$OUT" "sonnet" "--emit prints nothing on a mismatch"

# A difference OUTSIDE the declared keys is a plain mismatch again.
printf '{\n  "model": "sonnet",\n  "effortLevel": "high",\n  "permissions": {"deny": []}\n}\n' > "$SUB/ig/copy.json"
run_pinned verify "$SUB/ig/copy.json"
assert_exit "$RC" 11 "drift outside the ignored keys -> 11"
assert_contains "$OUT" "differences remain outside" "the refusal says where the difference is"

# A slot that keeps no witness of its own needs a CALLER-BROUGHT one; without
# any witness it stays strict. --baseline is a permanent interface, not a
# transitional shim: custody is opt-in, so "the caller held the last approved
# bytes" is an ordinary, supported case.
printf '{\n  "model": "sonnet",\n  "effortLevel": "high",\n  "permissions": {"deny": ["Bash"]}\n}\n' > "$SUB/ig/nocopy.json"
run_pinned verify "$SUB/ig/nocopy.json"
assert_exit "$RC" 11 "no stored witness and no --baseline -> 11"
assert_contains "$OUT" "no --baseline" "the note says what is missing"
printf '{\n  "model": "opus",\n  "effortLevel": "high",\n  "permissions": {"deny": ["Bash"]}\n}\n' > "$FIX/baseline.json"
run_pinned verify --baseline "$FIX/baseline.json" "$SUB/ig/nocopy.json"
assert_exit "$RC" 5 "a caller baseline that re-hashes to the record enables 5"
assert_contains "$OUT" "ignored-drift: model" "the baseline path names the drifted key"
printf 'not the approved bytes\n' > "$FIX/forged.json"
run_pinned verify --baseline "$FIX/forged.json" "$SUB/ig/nocopy.json"
assert_exit "$RC" 11 "a baseline that does not re-hash to the record is refused"
assert_contains "$OUT" "does not re-hash" "the refusal names the failed self-check"

# Duplicate object keys anywhere on either side: abort, never guess which
# occurrence a consumer's parser keeps.
printf '{"model": "sonnet", "effortLevel": "high", "effortLevel": "low", "permissions": {"deny": ["Bash"]}}\n' \
  > "$SUB/ig/copy.json"
run_pinned verify "$SUB/ig/copy.json"
assert_exit "$RC" 11 "duplicate object keys refuse the tolerance path -> 11"
assert_contains "$OUT" "duplicate object keys" "the refusal names the duplication"

# A non-JSON file simply never parses, so it always falls back to strict.
printf 'container\n' > "$SUB/ig/lane"
ANS='
y
'
run_pinned review --file "$SUB/ig/lane" --ignore-json-key model --store
assert_exit "$RC" 0 "pinned does not restrict WHICH paths may declare ignored keys"
printf 'vm\n' > "$SUB/ig/lane"
run_pinned verify "$SUB/ig/lane"
assert_exit "$RC" 11 "a non-JSON file falls back to the byte-exact verdict"
assert_contains "$OUT" "not exactly one JSON document" "the note says why it could not be compared"

# A declaration outside the recorded SHAPE disables the feature loudly -- it
# never silently tolerates more than it says. (A leftover dotted-line file
# from before the JSON format lands right here: it is not JSON, so it is
# refused rather than guessed at.)
printf '{"model": "sonnet", "permissions": {"deny": ["Bash"]}}\n' > "$SUB/ig/bad.json"
ANS='
y
'
run_pinned review --file "$SUB/ig/bad.json" --ignore-json-key model
assert_exit "$RC" 0 "fixture: bad.json approved with a declaration"
seed_state "$SUB/ig/bad.json" ignored.json 'model'
printf '{"model": "opus", "permissions": {"deny": ["Bash"]}}\n' > "$SUB/ig/bad.json"
run_pinned verify "$SUB/ig/bad.json"
assert_exit "$RC" 11 "an old dotted-line declaration refuses the tolerance path"
assert_contains "$OUT" "outside the ignored-key shape" "the refusal names the shape"
seed_state "$SUB/ig/bad.json" ignored.json '["model"]'
run_pinned verify "$SUB/ig/bad.json"
assert_exit "$RC" 11 "an array of STRINGS (not of paths) refuses the tolerance path"
assert_contains "$OUT" "outside the ignored-key shape" "the shape refusal names arrays of strings"
seed_state "$SUB/ig/bad.json" ignored.json '[]'
run_pinned verify "$SUB/ig/bad.json"
assert_exit "$RC" 11 "an empty declaration refuses (it tolerates nothing)"
assert_contains "$OUT" "declares no keys" "the refusal names the empty declaration"

# An UNDECLARED format refuses exactly like an unknown rev.<vcs>.
rm -f "$(slot_file_of "$SUB/ig/bad.json" ignored.json)"
seed_state "$SUB/ig/bad.json" ignored.toml 'model = true'
run_pinned verify "$SUB/ig/bad.json"
assert_exit "$RC" 11 "an unrecognized ignored.<format> refuses the tolerance path"
assert_contains "$OUT" "unsupported ignored-key format" "the refusal names the undeclared format"
seed_state "$SUB/ig/bad.json" ignored.json '[["model"]]'
run_pinned verify "$SUB/ig/bad.json"
assert_exit "$RC" 11 "two ignored.<format> files at once refuse"
assert_contains "$OUT" "more than one ignored" "the refusal names the ambiguity"
rm -f "$(slot_file_of "$SUB/ig/bad.json" ignored.toml)"

# The approved copy is a slot INVARIANT: if it exists it must re-hash to the
# record beside it. A violation is malformed state, not a degraded compare.
BAD_SLOT="$(slot_of "$SUB/ig/bad.json")"
printf 'tampered copy\n' > "$BAD_SLOT/approved"
chmod 640 "$BAD_SLOT/approved"
run_pinned verify "$SUB/ig/bad.json"
assert_exit "$RC" 1 "an approved copy that does not re-hash is a malformed slot (exit 1)"
assert_contains "$OUT" "malformed slot" "the error names the malformation"
assert_contains "$OUT" "re-approve" "the error names the remediation"

# Re-approving the same bytes with a DIFFERENT declaration is not a no-op,
# and clearing is loud. EVERY extra is re-stated by every ceremony, so a
# plain review clears the declaration and drops the stored witness together.
printf '{"model": "opus", "keep": 1}\n' > "$SUB/ig/clear.json"
CLEAR_SLOT="$(slot_of "$SUB/ig/clear.json")"
ANS='
y
'
run_pinned review --file "$SUB/ig/clear.json" --ignore-json-key model --store
assert_exit "$RC" 0 "fixture: clear.json approved with a declaration + stored copy"
ANS='
y
'
run_pinned review --file "$SUB/ig/clear.json"
assert_exit "$RC" 0 "re-approving identical bytes without a declaration still runs"
assert_missing  "$OUT" "already approved" "a changed declaration defeats the no-op short-circuit"
assert_contains "$OUT" "clearing the ignored keys" "the ceremony says the tolerance is being withdrawn"
assert_contains "$OUT" "drops the slot's stored copy" "and that custody is going with it"
assert_absent "$CLEAR_SLOT/ignored.json" "a plain review clears the declaration"
assert_absent "$CLEAR_SLOT/approved" "a plain review drops the stored copy"
printf '{"model": "sonnet", "keep": 1}\n' > "$SUB/ig/clear.json"
run_pinned verify "$SUB/ig/clear.json"
assert_exit "$RC" 11 "after clearing, the same drift is a plain mismatch again"

# Tombstoning retires the extras with the record.
printf '{"model": "opus"}\n' > "$SUB/ig/doomed.json"
DOOM_SLOT="$(slot_of "$SUB/ig/doomed.json")"
ANS='
y
'
run_pinned review --file "$SUB/ig/doomed.json" --ignore-json-key model --store
assert_exit "$RC" 0 "fixture: doomed.json approved with extras"
rm -f "$SUB/ig/doomed.json"
ANS='y
'
run_pinned tombstone "$SUB/ig/doomed.json"
assert_exit "$RC" 0 "tombstone succeeds"
assert_absent "$DOOM_SLOT/ignored.json" "tombstone drops the declaration"
assert_absent "$DOOM_SLOT/approved" "tombstone drops the approved copy"

# Surfaces: list annotates, status reports the declaration and the ~ state.
run_pinned list
assert_exit "$RC" 0 "list exits 0 with ignore-declaring slots present"
assert_contains "$OUT" "ignored:  model" "list annotates a slot that declares ignored keys"
assert_contains "$OUT" "$SUB/ig/nocopy.json" "list still prints the parseable row"
ANS=""
run_pinned status "$SUB/ig/nocopy.json"
assert_exit "$RC" 0 "status exits 0"
assert_contains "$OUT" "model, effortLevel" "status reports the declared keys"
assert_contains "$OUT" "re-approve with --store" "status says how a copy-less slot gets custody"
run_pinned status "$SUB/ig/copy.json"
assert_contains "$OUT" "live file differs" "status agrees with verify on a real mismatch"

# Argument surface.
ANS=""
run_pinned review --file "$SUB/ig/nocopy.json" --ignore-json-key 'permissions.deny[0]'
assert_exit "$RC" 1 "an out-of-grammar --ignore-json-key is refused up front"
assert_contains "$OUT" "outside the key grammar" "the refusal names the grammar"
# --store COMBINES FREELY. Custody serves the tolerant comparison, but also
# archives what was approved and feeds pinned cat, so it means something on a
# ceremony that declares nothing -- the old "--store applies to a ceremony
# that declares --ignore-json-key" pairing refusal must stay gone.
ANS='
n
'
run_pinned review --file "$SUB/ig/nocopy.json" --store
assert_exit "$RC" 0 "--store on a ceremony that declares NO ignored keys is accepted"
assert_missing "$OUT" "--store applies to a ceremony" "the retired pairing refusal does not come back"
assert_contains "$OUT" "kept in the slot" "custody stands on its own in the display"
# It is still the FILE ceremony's flag: a repo review has no bytes to keep.
ANS=""
run_pinned review "$SUB" --store
assert_exit "$RC" 1 "--store outside the --file ceremony is refused"
assert_contains "$OUT" "--store applies to the --file ceremony only" "the refusal names the ceremony"
run_pinned review --ignore-json-key model --file "$SUB/ig/nocopy.json"
assert_exit "$RC" 1 "--ignore-json-key before any --file is refused"
assert_contains "$OUT" "must follow the --file" "the refusal names the ordering rule"

# Unit-level: the projection guard and the path builder, through the probe.
run_probe ign_paths_json "model effortLevel statusLine.command"
assert_eq "$POUT" '[["model"],["effortLevel"],["statusLine","command"]]' \
          "ign_paths_json builds the jq path array"
printf '{"a":{"x":1},"a":{"y":2}}\n' > "$FIX/dup.json"
run_probe json_projectable "$FIX/dup.json" side
assert_exit "$RC" 1 "json_projectable refuses object-valued duplicate keys"
printf '{"a":{"x":1},"b":{"y":2}}\n' > "$FIX/clean.json"
run_probe json_projectable "$FIX/clean.json" side
assert_exit "$RC" 0 "json_projectable accepts a duplicate-free document"
printf '{"a":1}{"b":2}\n' > "$FIX/two.json"
run_probe json_projectable "$FIX/two.json" side
assert_exit "$RC" 1 "json_projectable refuses a concatenated document stream"
printf '{"a":1}\000' > "$FIX/nul.json"
run_probe json_projectable "$FIX/nul.json" side
assert_exit "$RC" 1 "json_projectable refuses NUL bytes jq would tolerate"
run_probe ign_key_path_json "statusLine.command"
assert_eq "$POUT" '["statusLine","command"]' "ign_key_path_json builds one jq path"
fi

# ---------------------------------------------------------------------------
say "S10: the ignorable policy (tiers, ceremony, enforcement)"
# ---------------------------------------------------------------------------
# The ladder: machine policy >= user policy >= slot declaration >= tolerated
# drift. Every rung is jq-shaped, so this section needs jq exactly like S9.
if ! command -v jq >/dev/null 2>&1; then
  say "S10: SKIPPED (no jq in the trusted PATH)"
else
mkdir -p "$SUB/pol/in" "$SUB/pol/inx"
JSON_IN='{"model": "opus", "keep": 1}'
printf '%s\n' "$JSON_IN" > "$SUB/pol/in/s.json"
printf '%s\n' "$JSON_IN" > "$SUB/pol/inx/s.json"

# An absent user tier grants nothing: the ceremony refuses, and says exactly
# which command grants it. This is also the first-deploy state, so a refusal
# here must never read as breakage.
rm -f "$POLICY_USER" "$PINNED_MACHINE_POLICY"
ANS='
y
'
run_pinned review --file "$SUB/pol/in/s.json" --ignore-json-key model
assert_exit "$RC" 1 "no policy at all -> the ceremony refuses the declaration"
assert_contains "$OUT" "does not grant these keys" "the refusal names the missing grant"
assert_contains "$OUT" "sudo pinned ignorable add model --under $SUB/pol/in" \
                "the refusal names the exact grant command"
assert_absent "$(slot_file_of "$SUB/pol/in/s.json" pin.sha256)" "nothing was recorded"

ANS=""
run_pinned ignorable list
assert_exit "$RC" 0 "ignorable list runs unprivileged with no policy at all"
assert_contains "$OUT" "no machine constraint" "list says the machine tier is absent"
assert_contains "$OUT" "nothing is ignorable" "list says an absent user tier grants nothing"

# The grant ceremony writes the user tier.
ANS='y
'
run_pinned ignorable add model --under "$SUB/pol/in"
assert_exit "$RC" 0 "ignorable add succeeds"
assert_contains "$OUT" "granted" "the ceremony confirms the grant"
assert_contains "$OUT" "under $SUB/pol/in" "the ceremony states the scope"
assert_file "$POLICY_USER" "the user tier is written"
assert_eq "$(jq -c . "$POLICY_USER")" "[{\"path\":[\"model\"],\"under\":\"$SUB/pol/in\"}]" \
          "the entry is {path, under}"

ANS='y
'
run_pinned ignorable add model --under "$SUB/pol/in"
assert_exit "$RC" 1 "a duplicate grant is refused"
assert_contains "$OUT" "already granted" "the duplicate refusal names the reason"
ANS='y
'
run_pinned ignorable add model --under "relative/dir"
assert_exit "$RC" 1 "a relative --under is refused"
assert_contains "$OUT" "absolute" "the refusal names the requirement"
ANS='y
'
run_pinned ignorable remove effortLevel --under "$SUB/pol/in"
assert_exit "$RC" 1 "removing an entry that does not exist is refused"
assert_contains "$OUT" "no such grant" "the refusal names the missing entry"
ANS='y
'
run_pinned ignorable remove model
assert_exit "$RC" 1 "removing the same key at a DIFFERENT scope is refused"
assert_contains "$OUT" "no such grant" "remove matches key AND scope"

ANS=""
run_pinned ignorable list
assert_exit "$RC" 0 "ignorable list exits 0 with a user tier"
assert_contains "$OUT" "effective" "list shows the effective intersection"
assert_contains "$OUT" "under $SUB/pol/in" "list shows each entry's scope"

# In scope the ceremony proceeds; one component further along it refuses --
# the same boundary rule list --under uses (/pol/in is not /pol/inx).
ANS='
y
'
run_pinned review --file "$SUB/pol/in/s.json" --ignore-json-key model --store
assert_exit "$RC" 0 "a granted key in scope approves"
assert_contains "$OUT" "granted by user policy, under $SUB/pol/in: model" "provenance names the scope"

# MIXED SCOPES: keys whose grants reach differently cannot share one clause,
# so the collapsed line names the reach per key instead.
seed_policy_user "[{\"path\":[\"model\"],\"under\":\"$SUB/pol/in\"},{\"path\":[\"effortLevel\"]}]"
printf '{"model": "opus", "effortLevel": "high", "keep": 1}\n' > "$SUB/pol/in/m.json"
ANS='
y
'
run_pinned review --file "$SUB/pol/in/m.json" --ignore-json-key model --ignore-json-key effortLevel
assert_exit "$RC" 0 "two granted keys at different scopes approve"
assert_contains "$OUT" "granted by user policy: model (under $SUB/pol/in), effortLevel (everywhere)" \
                "mixed scopes name each key's reach"
seed_policy_user "[{\"path\":[\"model\"],\"under\":\"$SUB/pol/in\"}]"

ANS='
y
'
run_pinned review --file "$SUB/pol/inx/s.json" --ignore-json-key model
assert_exit "$RC" 1 "the same key one component off the scope is refused"
assert_contains "$OUT" "does not grant these keys" "the near-miss refusal is the policy refusal"

# NARROWING BITES IMMEDIATELY: the grant is checked at USE time, so
# withdrawing it turns the tolerated drift back into a plain mismatch with
# no re-ceremony anywhere.
printf '{"model": "sonnet", "keep": 1}\n' > "$SUB/pol/in/s.json"
ANS=""
run_pinned verify "$SUB/pol/in/s.json"
assert_exit "$RC" 5 "drift in a granted, declared key -> 5"
ANS='y
'
run_pinned ignorable remove model --under "$SUB/pol/in"
assert_exit "$RC" 0 "the grant is withdrawn"
assert_contains "$OUT" "withdrawn" "the ceremony confirms the withdrawal"
ANS=""
run_pinned verify "$SUB/pol/in/s.json"
assert_exit "$RC" 11 "the recorded key loses its grant -> plain 11, no re-ceremony"
assert_contains "$OUT" "no longer grants" "the note says the grant is gone"
assert_contains "$OUT" "model" "the note names the key that lost it"

# MACHINE TIER: the effective policy is the intersection. A user entry the
# machine tier does not cover grants nothing, even though it is recorded.
seed_policy_user "[{\"path\":[\"model\"]}]"
seed_policy_machine "[{\"path\":[\"model\"],\"under\":\"$SUB/pol/in\"}]"
ANS=""
run_pinned ignorable list
assert_exit "$RC" 0 "list exits 0 with both tiers"
assert_contains "$OUT" "everywhere" "the user tier's unscoped entry is shown"
printf '%s\n' "$JSON_IN" > "$SUB/pol/in/s.json"
ANS='
y
'
run_pinned review --file "$SUB/pol/in/s.json" --ignore-json-key model
assert_exit "$RC" 1 "an unscoped user grant is NOT covered by a scoped machine entry"
assert_contains "$OUT" "does not grant these keys" "the intersection refuses it"

# Narrower than the machine scope is inside it; equal is inside it too.
seed_policy_user "[{\"path\":[\"model\"],\"under\":\"$SUB/pol/in/deeper\"}]"
mkdir -p "$SUB/pol/in/deeper"
printf '%s\n' "$JSON_IN" > "$SUB/pol/in/deeper/s.json"
ANS='
y
'
run_pinned review --file "$SUB/pol/in/deeper/s.json" --ignore-json-key model --store
assert_exit "$RC" 0 "a user scope BELOW the machine scope survives the intersection"
assert_contains "$OUT" "under $SUB/pol/in/deeper" "provenance names the narrower scope"
assert_contains "$OUT" "within the machine policy at $PINNED_MACHINE_POLICY" \
                "the machine tier is folded into the same provenance line"

# An unusable tier grants nothing -- on either rung, at both ends.
seed_policy_machine '{"path": ["model"]}'
ANS='
y
'
run_pinned review --file "$SUB/pol/in/deeper/s.json" --ignore-json-key model
assert_exit "$RC" 1 "an unusable machine tier stops the ceremony"
assert_contains "$OUT" "not a valid ignorable policy" "the refusal names the invalid tier"
printf '{"model": "sonnet", "keep": 1}\n' > "$SUB/pol/in/deeper/s.json"
ANS=""
run_pinned verify "$SUB/pol/in/deeper/s.json"
assert_exit "$RC" 11 "an unusable policy refuses the tolerance path at verify too"
assert_contains "$OUT" "cannot be read" "the note says the policy could not be read"

seed_policy_machine '[{"path": ["model"], "nope": 1}]'
ANS=""
run_pinned ignorable list
assert_exit "$RC" 1 "an entry with an unknown key is refused (it could be a constraint)"
seed_policy_machine "[{\"path\":[\"model\"],\"under\":\"relative\"}]"
ANS=""
run_pinned ignorable list
assert_exit "$RC" 1 "a non-absolute under is refused"
rm -f "$PINNED_MACHINE_POLICY"

# ensure_tree SELF-HEALS the allowed_signers move, loudly, at the next root
# ceremony -- and leaves the old directory behind only if something else is
# still in it.
mkdir -p "$PINNED_ROOT/$USERNAME/signers"
printf 'harness ssh-ed25519 AAAAfake\n' > "$PINNED_ROOT/$USERNAME/signers/allowed_signers"
chmod 640 "$PINNED_ROOT/$USERNAME/signers/allowed_signers"
printf '%s\n' "$JSON_IN" > "$SUB/pol/heal.json"
ANS='
y
'
run_pinned review --file "$SUB/pol/heal.json"
assert_exit "$RC" 0 "a root ceremony runs with a legacy signers/ dir present"
assert_contains "$OUT" "moved allowed_signers into the policy dir" "the move is announced"
assert_file "$PINNED_ROOT/$USERNAME/policy/allowed_signers" "allowed_signers now lives in policy/"
assert_eq "$(cat "$PINNED_ROOT/$USERNAME/policy/allowed_signers")" "harness ssh-ed25519 AAAAfake" \
          "the moved file keeps its content"
assert_absent "$PINNED_ROOT/$USERNAME/signers" "the emptied legacy dir is removed"
assert_missing "$OUT" "note: removed the now-empty legacy dir" \
               "the removal rides the move-note when one run does both"

# An EARLIER run did the move and left the empty dir behind: the removal is
# then a note of its own, never a continuation indented under nothing.
mkdir -p "$PINNED_ROOT/$USERNAME/signers"
printf '%s\n' "$JSON_IN" > "$SUB/pol/heal2.json"
ANS='
y
'
run_pinned review --file "$SUB/pol/heal2.json"
assert_exit "$RC" 0 "a root ceremony runs with an empty legacy signers/ dir"
assert_missing "$OUT" "moved allowed_signers" "there was nothing left to move"
assert_contains "$OUT" "note: removed the now-empty legacy dir" \
                "the orphaned removal stands on its own note"
assert_absent "$PINNED_ROOT/$USERNAME/signers" "the empty legacy dir is removed too"
fi

# ---------------------------------------------------------------------------
say "S11: slot (the name resolver)"
# ---------------------------------------------------------------------------
# `slot` prints ONE line -- the slot directory -- for any path, and never
# answers existence. Lane launchers select their launch payload with it, so
# the encoding must never be reimplemented outside pinned.
mkdir -p "$SUB/s"
printf '{"measured": true}\n' > "$SUB/s/measured.json"
ANS='
y
'
run_pinned review --file "$SUB/s/measured.json"
assert_exit "$RC" 0 "fixture: measured.json approved"
ANS=""
run_pinned slot "$SUB/s/measured.json"
assert_exit "$RC" 0 "slot on a measured FILE exits 0"
assert_eq "$(cat "$OUT")" "$(slot_of "$SUB/s/measured.json")" "slot prints one line: the slot dir"
assert_file "$(cat "$OUT")/pin.sha256" "the printed dir is the one the ceremony wrote"

run_pinned slot "$SUB/s/absent/never-written.json"
assert_exit "$RC" 0 "slot on an ABSENT path under an existing dir exits 0"
assert_eq "$(cat "$OUT")" "$(slot_of "$SUB/s/absent/never-written.json")" \
          "an absent path resolves to its slot dir (a name, not an oracle)"
assert_absent "$(cat "$OUT")" "and that dir does not exist -- consumers guard with -d"

run_pinned slot "$SUB/s/gone/../x"
assert_exit "$RC" 1 "a '..' tail below a missing directory refuses"
assert_contains "$OUT" ".. below a missing directory" "the refusal names the reason"

run_pinned slot "$SUB/l"
assert_exit "$RC" 0 "slot on a plain DIRECTORY exits 0 (no git work tree needed)"
assert_eq "$(cat "$OUT")" "$(slot_of "$SUB/l")" "a directory encodes exactly like a file"
DIR_SLOT="$(cat "$OUT")"
run_pinned slot "$SUB/l/"
assert_eq "$(cat "$OUT")" "$DIR_SLOT" "a trailing slash resolves to the same slot"

run_pinned slot "$SUB/s/measured.json" "$SUB/s/absent/never-written.json"
assert_exit "$RC" 1 "slot takes exactly one path"

# ---------------------------------------------------------------------------
say "S12: cat (custody's verified reader)"
# ---------------------------------------------------------------------------
# Custody without a verified reader would invite consumers to open slot files
# directly, which is the one thing nothing outside pinned may do. cat is that
# reader: it re-hashes the stored witness against the record and only then
# emits it, and it puts NOTHING on stdout in any failure case -- which is why
# these cases use the split-stream driver.
mkdir -p "$SUB/c"
printf '{"served": true}\n' > "$SUB/c/served.json"
CAT_SLOT="$(slot_of "$SUB/c/served.json")"
ANS='
y
'
run_pinned review --file "$SUB/c/served.json" --store
assert_exit "$RC" 0 "fixture: served.json approved with custody"
ANS=""
run_pinned_split cat "$SUB/c/served.json"
assert_exit "$RC" 0 "a witness that re-hashes to the record is served -> 0"
if cmp -s "$OUT" "$SUB/c/served.json"; then
  ok "cat emits the approved bytes, byte for byte and undecorated"
else
  fail "cat's output differs from the approved bytes"
fi

# DELIBERATE: cat serves even when the live file has DRIFTED. A consumer on
# this rung reads custody, not the live path -- the approved bytes are the
# content it is entitled to, and the live file is the editing surface waiting
# for its next ceremony. Whether the two agree is verify's question.
printf '{"served": false}\n' > "$SUB/c/served.json"
run_pinned verify "$SUB/c/served.json"
assert_exit "$RC" 11 "the drifted live file is a mismatch for verify"
run_pinned_split cat "$SUB/c/served.json"
assert_exit "$RC" 0 "cat serves DESPITE live drift -- one job per verb"
assert_eq "$(cat "$OUT")" '{"served": true}' "and serves the APPROVED bytes, not the live ones"
printf '{"served": true}\n' > "$SUB/c/served.json"

# 16: a valid record with no witness at all. New code, tens class, because
# the ceremony is what fixes it.
printf 'no custody here\n' > "$SUB/c/bare.txt"
ANS='
y
'
run_pinned review --file "$SUB/c/bare.txt"
assert_exit "$RC" 0 "fixture: bare.txt approved without --store"
ANS=""
run_pinned_split cat "$SUB/c/bare.txt"
assert_exit "$RC" 16 "a record with no stored witness -> 16"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "keeps no approved copy" "16 names what is missing"
assert_contains "$ERRF" "--store" "16 names the remediation"

run_pinned_split cat "$SUB/c/never-pinned.txt"
assert_exit "$RC" 10 "no record for the path -> 10"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "no slot" "10 names the state"

seed_tombstone "$SUB/c/retired.txt"
run_pinned_split cat "$SUB/c/retired.txt"
assert_exit "$RC" 13 "a tombstoned path -> 13"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "no approved content to serve" "13 says why there is nothing"

# THE WITNESS INVARIANT: a witness can only ever NARROW a comparison, never
# stand in for the live file. A file that is GONE is 20 for both verbs --
# custody does not rescue it, and must not go on serving a removed file's
# content to consumers that never notice it went.
printf 'here for now\n' > "$SUB/c/vanish.txt"
VANISH_SLOT="$(slot_of "$SUB/c/vanish.txt")"
ANS='
y
'
run_pinned review --file "$SUB/c/vanish.txt" --store
assert_exit "$RC" 0 "fixture: vanish.txt approved with custody"
assert_file "$VANISH_SLOT/approved" "the witness is in the slot"
rm -f "$SUB/c/vanish.txt"
ANS=""
run_pinned verify "$SUB/c/vanish.txt"
assert_exit "$RC" 20 "a stored witness does not rescue a missing file: verify still 20"
run_pinned_split cat "$SUB/c/vanish.txt"
assert_exit "$RC" 20 "and cat refuses to serve a removed file -> 20"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "custody does not serve a removed file" "20 names the rule"

# A witness that does not re-hash is a MALFORMED SLOT, the same class verify
# hard-errors on: root-owned bytes that are not the approved bytes are
# incoherent state, not weak evidence.
printf 'tampered witness\n' > "$CAT_SLOT/approved"
chmod 600 "$CAT_SLOT/approved"
run_pinned_split cat "$SUB/c/served.json"
assert_exit "$RC" 1 "a witness that does not re-hash -> 1"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "malformed slot" "the error names the malformation"
assert_contains "$ERRF" "re-approve" "the error names the remediation"

# 30 is the slot's own ownership/mode invariant. verify answers 1 here (for a
# gate, a record it cannot trust is a structural failure of the tool); cat
# answers 30, because for a READER it is the same class as a wrong-mode live
# file -- something chmod fixes, not something to re-approve.
ANS='
y
'
run_pinned review --file "$SUB/c/served.json" --store
assert_exit "$RC" 0 "fixture: served.json re-approved to reset the slot"
ANS=""
chmod 660 "$CAT_SLOT/approved"
run_pinned_split cat "$SUB/c/served.json"
assert_exit "$RC" 30 "a group-writable witness -> 30"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "group/other-writable" "30 names the invariant"
chmod 600 "$CAT_SLOT/approved"
run_pinned_split cat "$SUB/c/served.json"
assert_exit "$RC" 0 "the remediated slot serves again"

# A repo slot has no custody to serve: content lives in git, addressed by the
# rev the slot records.
run_pinned_split cat "$SUB/handwritten.conf"
assert_exit "$RC" 1 "a repo slot refuses -- custody is a file-pin concept"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"
assert_contains "$ERRF" "git" "the refusal names the repo-side equivalent"
assert_contains "$ERRF" "pinned slot" "and the resolver that gets you the rev"

run_pinned_split cat "$SUB/c/served.json" "$SUB/c/bare.txt"
assert_exit "$RC" 1 "cat takes exactly one path"
assert_eq "$(cat "$OUT")" "" "nothing reaches stdout"

# ---------------------------------------------------------------------------
say "S13: show (file rehearsal, repo re-display)"
# ---------------------------------------------------------------------------
# The repo branch re-displays what the pin NAMES and records nothing, so the
# slot is asserted byte-identical across a show -- names and contents, never
# mtimes (a show that only touched a timestamp would still be a write, but
# the invariant under test is that no state changes).
slot_snapshot() { # slot-dir -> one digest over every name and every byte in it
  { find "$1" | sort; find "$1" -type f | sort | xargs cat; } | shasum -a 256 | awk '{print $1}'
}

if [ "$GIT_OK" -eq 1 ]; then
  REPO_R="$FIX/reviewfix"
  mkdir -p "$REPO_R"
  bgit "$REPO_R" init -q
  printf 'alpha line\n' > "$REPO_R/r.txt"
  bgit "$REPO_R" add r.txt; bgit "$REPO_R" commit -q -m "r1 base"
  R_SLOT="$(slot_of "$REPO_R")"

  # Nothing to re-display before a ceremony has named something.
  ANS=""
  run_pinned show "$REPO_R"
  assert_exit "$RC" 1 "show of an unpinned repo refuses"
  assert_contains "$OUT" "no pin for $REPO_R; show re-displays a pin (review it first)" \
    "the refusal names the missing pin and the remedy"
  assert_absent "$R_SLOT" "a refused show creates no slot dir"

  ANS='
y
'
  run_pinned review "$REPO_R"
  assert_exit "$RC" 0 "fixture: the repo is pinned at its base commit"
  R_PIN="$(cat "$R_SLOT/rev.git")"
  R_SNAP="$(slot_snapshot "$R_SLOT")"

  ANS=""
  run_pinned show "$REPO_R"
  assert_exit "$RC" 0 "show of a pinned repo exits 0"
  assert_contains "$OUT" "$R_PIN" "show prints the pinned hash"
  assert_contains "$OUT" "full tree at" "show displays the pinned tree"
  assert_contains "$OUT" "+alpha line" "the display carries the pinned content"
  assert_contains "$OUT" "live HEAD is at the pin" "HEAD == pin reads as such"
  assert_eq "$(slot_snapshot "$R_SLOT")" "$R_SNAP" "show writes nothing into the slot"

  # Past the pin: the orientation line counts, and the DISPLAY still shows the
  # pin -- content added after it must not appear anywhere in the display.
  printf 'beta line\n' >> "$REPO_R/r.txt"
  bgit "$REPO_R" commit -q -am "r2 second"
  ANS=""
  run_pinned show "$REPO_R"
  assert_exit "$RC" 0 "show with HEAD past the pin exits 0"
  assert_contains "$OUT" "live HEAD is 1 commit past the pin" "orientation counts the commits past the pin, singular"
  assert_contains "$OUT" "+alpha line" "the pinned content is still what is displayed"
  assert_missing "$OUT" "beta line" "content past the pin never reaches the display"
  assert_eq "$(slot_snapshot "$R_SLOT")" "$R_SNAP" "still no slot write"

  # A rewritten pin commit: HEAD is a different history, not a descendant.
  bgit "$REPO_R" reset -q --hard "$R_PIN"
  bgit "$REPO_R" commit -q --amend -m "r1 rewritten"
  ANS=""
  run_pinned show "$REPO_R"
  assert_exit "$RC" 0 "show against a rewritten history exits 0"
  assert_contains "$OUT" "does not descend from the pin" "a non-descending HEAD is named as such"
  assert_contains "$OUT" "+alpha line" "the pinned rev is still displayed from the object store"

  # A declared release name is part of what the pin says.
  printf 'v1.2.3\n' > "$R_SLOT/tag"
  chmod 640 "$R_SLOT/tag"
  ANS=""
  run_pinned show "$REPO_R"
  assert_exit "$RC" 0 "show with a declared tag exits 0"
  assert_contains "$OUT" "v1.2.3" "the declared tag is shown"
  assert_contains "$OUT" "(declared)" "and is labelled as declared, not verified"

  # The file ceremony's flags say nothing about a rev -- refused, not ignored.
  ANS=""
  run_pinned show "$REPO_R" --algo sha256
  assert_exit "$RC" 1 "--algo is refused on a repo"
  assert_contains "$OUT" "--algo/--length apply to the file display" "the refusal names the mode"
  run_pinned show "$REPO_R" --length 512
  assert_exit "$RC" 1 "--length is refused on a repo"
  assert_contains "$OUT" "--algo/--length apply to the file display" "same refusal for --length"

  # A directory with no repo of its own. WHICH refusal fires depends on the
  # scratch dir's own surroundings: outside any repo it is resolve_repo's "not
  # a usable git work tree", but a $TMPDIR that happens to sit inside some
  # other repository (a project-local .tmp/) makes git answer yes and the
  # work-tree-root refusal fires instead. Both are loud, and either is the
  # contract under test -- neither displays anything.
  mkdir -p "$FIX/notarepo"
  ANS=""
  run_pinned show "$FIX/notarepo"
  assert_exit "$RC" 1 "a directory with no pin of its own refuses"
  if grep -qE 'not a usable git work tree|not the work-tree root' "$OUT"; then
    ok "the refusal is resolve_repo's, never a display"
  else
    fail "unexpected refusal for a non-repo directory: $(cat "$OUT")"
  fi
  assert_missing "$OUT" "full tree at" "nothing is displayed for it"

  # A subdirectory of a real repo: a pin names the whole repo, so a slot
  # keyed on a subdir could only mislead (deploy matches inputs by root; a
  # root slot and a subdir slot could pin one repo at two revs). resolve_repo
  # refuses and names the root -- for every verb that resolves a repo.
  mkdir -p "$REPO_R/subdir"
  ANS=""
  run_pinned show "$REPO_R/subdir"
  assert_exit "$RC" 1 "a subdirectory of a repo refuses"
  assert_contains "$OUT" "not the work-tree root: $REPO_R/subdir" "the refusal names the subdir"
  assert_contains "$OUT" "name its root: $REPO_R" "and the root remediation"
  ANS=""
  run_pinned status "$REPO_R/subdir"
  assert_exit "$RC" 1 "status refuses the same subdirectory"
  assert_contains "$OUT" "not the work-tree root" "through the shared resolver"
else
  say "S13: SKIPPED (no git fixture) -- file cases below still run"
fi

# The file rehearsal is unchanged by the repo branch: a regular file still
# takes the hash-and-wrapper path, flags included.
printf 'hook body\n' > "$SUB/reviewme.sh"
ANS=""
run_pinned show "$SUB/reviewme.sh"
assert_exit "$RC" 0 "show of a regular file exits 0"
assert_contains "$OUT" "$(digest_of "$SUB/reviewme.sh")" "the file display prints the file's sha256"
assert_contains "$OUT" "hook body" "the reviewed bytes are displayed"
assert_contains "$OUT" "fail-closed wrapper" "the file display still emits the wrapper"
run_pinned show "$SUB/reviewme.sh" --algo sha512
assert_exit "$RC" 0 "--algo still applies to the file display"
run_pinned show "$SUB/no-such-file"
assert_exit "$RC" 1 "a missing path is still a file-display refusal"
assert_contains "$OUT" "not a regular file" "and says so"

# ---------------------------------------------------------------------------
say "S14: mv (re-key a record to a moved path)"
# ---------------------------------------------------------------------------
# mv carries a record VERBATIM to the path its content moved to. The cases
# below are the two halves of that claim: what travels (record, annotations,
# tombstone at the old key) and what the machine refuses to move (anything it
# cannot prove the new path already holds).
mkdir -p "$SUB/mv"

# --- file happy path: the check line is re-named, the digest is not --------
printf 'moving bytes\n' > "$SUB/mv/from.txt"
MV_DIG="$(digest_of "$SUB/mv/from.txt")"
ANS='
y
'
run_pinned review --file "$SUB/mv/from.txt" --store
assert_exit "$RC" 0 "fixture: the file record exists"
MV_OLD_SLOT="$(slot_of "$SUB/mv/from.txt")"
mkdir -p "$SUB/mv/deeper"
mv "$SUB/mv/from.txt" "$SUB/mv/deeper/to.txt"
MV_NEW_SLOT="$(slot_of "$SUB/mv/deeper/to.txt")"
ANS='y
'
run_pinned mv "$SUB/mv/from.txt" "$SUB/mv/deeper/to.txt"
assert_exit "$RC" 0 "a file record moves to the path its content moved to"
assert_contains "$OUT" "at the new path" "the ceremony states what the y buys"
assert_contains "$OUT" "the approved copy" "and names the annotations that travel"
assert_file "$MV_NEW_SLOT/pin.sha256" "the new slot holds the record"
assert_eq "$(cat "$MV_NEW_SLOT/pin.sha256")" "$MV_DIG  $SUB/mv/deeper/to.txt" \
          "the check line keeps the digest and names the NEW path"
assert_eq "$(count_state "$MV_NEW_SLOT")" 1 "the new slot holds exactly one state file"
if (cd / && shasum -a 256 -c "$MV_NEW_SLOT/pin.sha256" >/dev/null 2>&1); then
  ok "shasum -c still verifies the moved record at its new path"
else
  fail "shasum -c cross-check broke on the moved record"
fi
assert_file "$MV_NEW_SLOT/approved" "the stored witness travelled"
assert_eq "$(digest_of "$MV_NEW_SLOT/approved")" "$MV_DIG" "and it is the same approved bytes"
assert_file "$MV_OLD_SLOT/tombstone" "the old key is tombstoned, not deleted"
assert_contains "$MV_OLD_SLOT/tombstone" "moved to $SUB/mv/deeper/to.txt" \
                "the tombstone names where the record went"
assert_eq "$(count_state "$MV_OLD_SLOT")" 1 "the old slot holds exactly one state file"
assert_absent "$MV_OLD_SLOT/approved" "the old slot keeps no copy of content it no longer records"
ANS=""
run_pinned verify "$SUB/mv/deeper/to.txt"
assert_exit "$RC" 0 "the moved file verifies at its new path"
run_pinned verify "$SUB/mv/from.txt"
assert_exit "$RC" 0 "the old path verifies 0 while it stays gone (tombstoned)"
printf 'squatter\n' > "$SUB/mv/from.txt"
run_pinned verify "$SUB/mv/from.txt"
assert_exit "$RC" 13 "content reappearing at the old path fails closed (13)"
rm -f "$SUB/mv/from.txt"

# --- decline changes nothing ----------------------------------------------
printf 'declined move\n' > "$SUB/mv/dfrom.txt"
ANS='
y
'
run_pinned review --file "$SUB/mv/dfrom.txt"
assert_exit "$RC" 0 "fixture: the declined-move record exists"
DECL_OLD="$(slot_of "$SUB/mv/dfrom.txt")"
DECL_NEW="$(slot_of "$SUB/mv/dto.txt")"
mv "$SUB/mv/dfrom.txt" "$SUB/mv/dto.txt"
ANS='n
'
run_pinned mv "$SUB/mv/dfrom.txt" "$SUB/mv/dto.txt"
assert_exit "$RC" 2 "declining the mv exits 2"
assert_contains "$OUT" "both slots unchanged" "and says nothing moved"
assert_file "$DECL_OLD/pin.sha256" "the old record is untouched"
assert_absent "$DECL_OLD/tombstone" "no tombstone was written"
assert_absent "$DECL_NEW" "the new slot was never created"

# --- the refuse matrix -----------------------------------------------------
ANS=""
run_pinned mv "$SUB/mv/dto.txt"
assert_exit "$RC" 1 "mv with one path is usage (exit 1)"
assert_contains "$OUT" "usage: pinned" "and prints usage"
run_pinned mv "$SUB/mv/dto.txt" "$SUB/mv/dto.txt"
assert_exit "$RC" 1 "old and new naming one path refuses"
assert_contains "$OUT" "name the same path" "the refusal says why"

printf 'still live\n' > "$SUB/mv/live.txt"
ANS='
y
'
run_pinned review --file "$SUB/mv/live.txt"
assert_exit "$RC" 0 "fixture: a record whose path is still live"
printf 'copy at the new path\n' > "$SUB/mv/live-copy.txt"
ANS=""
run_pinned mv "$SUB/mv/live.txt" "$SUB/mv/live-copy.txt"
assert_exit "$RC" 1 "mv refuses while the old path still exists"
assert_contains "$OUT" "has already moved" "the refusal names the premise"

run_pinned mv "$SUB/mv/never-approved.txt" "$SUB/mv/live-copy.txt"
assert_exit "$RC" 1 "mv refuses a path that was never approved"
assert_contains "$OUT" "was never approved" "and says there is no record to move"

seed_tombstone "$SUB/mv/retired.txt"
run_pinned mv "$SUB/mv/retired.txt" "$SUB/mv/live-copy.txt"
assert_exit "$RC" 1 "mv refuses a tombstoned record"
assert_contains "$OUT" "does not travel" "a tombstone is the old path's own history"

# An occupied new slot: records do not merge, in either direction.
printf 'occupant\n' > "$SUB/mv/occupied.txt"
printf 'mover\n' > "$SUB/mv/mover.txt"
ANS='
y
'
run_pinned review --file "$SUB/mv/occupied.txt"
ANS='
y
'
run_pinned review --file "$SUB/mv/mover.txt"
assert_exit "$RC" 0 "fixture: two records, both live"
MOVER_SLOT="$(slot_of "$SUB/mv/mover.txt")"
rm -f "$SUB/mv/mover.txt"
ANS=""
run_pinned mv "$SUB/mv/mover.txt" "$SUB/mv/occupied.txt"
assert_exit "$RC" 1 "mv refuses a new path that already has a record"
assert_contains "$OUT" "records do not merge" "the refusal names the rule"
assert_absent "$MOVER_SLOT/tombstone" "the old record is left alone"

# A state-free slot is not an empty one: `signer add --repo` leaves per-slot
# signer data behind, and a record landing on it would silently inherit them.
printf 'signer squat\n' > "$SUB/mv/signed-target.txt"
SIGNED_SLOT="$(slot_of "$SUB/mv/signed-target.txt")"
mkdir -p "$SIGNED_SLOT/signers"
printf 'harness@example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n' \
  > "$SIGNED_SLOT/signers/allowed_signers"
chmod 640 "$SIGNED_SLOT/signers/allowed_signers"
ANS=""
run_pinned mv "$SUB/mv/mover.txt" "$SUB/mv/signed-target.txt"
assert_exit "$RC" 1 "mv refuses a signers-only slot at the new path"
assert_contains "$OUT" "per-slot signer data" "the refusal names the signer data by role"

# Content that is not what the record names, at the new path.
printf 'original bytes\n' > "$SUB/mv/drifter.txt"
ANS='
y
'
run_pinned review --file "$SUB/mv/drifter.txt"
assert_exit "$RC" 0 "fixture: the drift record exists"
DRIFT_SLOT="$(slot_of "$SUB/mv/drifter.txt")"
rm -f "$SUB/mv/drifter.txt"
printf 'different bytes\n' > "$SUB/mv/drifted-to.txt"
ANS=""
run_pinned mv "$SUB/mv/drifter.txt" "$SUB/mv/drifted-to.txt"
assert_exit "$RC" 1 "mv refuses content at the new path that is not what the record names"
assert_contains "$OUT" "is not what" "the refusal says the content does not answer to the record"
assert_absent "$DRIFT_SLOT/tombstone" "and nothing was written"
run_pinned mv "$SUB/mv/drifter.txt" "$SUB/mv/absent-entirely.txt"
assert_exit "$RC" 1 "mv refuses when nothing is at the new path"
assert_contains "$OUT" "not a regular file" "and says the new path is not a file"

# --- tolerated drift: the record still names this content ------------------
if command -v jq >/dev/null 2>&1; then
  # The declared keys' grant has to hold at mv time exactly as at verify time,
  # so the ceremony's tolerance is the gate's tolerance and nothing else.
  seed_policy_user '[{"path":["model"]}]'
  printf '{\n  "model": "opus",\n  "keep": 1\n}\n' > "$SUB/mv/tol.json"
  TOL_DIG="$(digest_of "$SUB/mv/tol.json")"
  ANS='
y
'
  run_pinned review --file "$SUB/mv/tol.json" --ignore-json-key model --store
  assert_exit "$RC" 0 "fixture: a record that declares an ignored key, with custody"
  rm -f "$SUB/mv/tol.json"
  printf '{\n  "model": "sonnet",\n  "keep": 1\n}\n' > "$SUB/mv/tol-moved.json"
  TOL_NEW_SLOT="$(slot_of "$SUB/mv/tol-moved.json")"
  ANS='y
'
  run_pinned mv "$SUB/mv/tol.json" "$SUB/mv/tol-moved.json"
  assert_exit "$RC" 0 "drift confined to a declared ignored key still moves"
  assert_contains "$OUT" "not byte-identical" "the ceremony says so loudly"
  assert_contains "$OUT" "model" "and names the key that drifted"
  assert_eq "$(cat "$TOL_NEW_SLOT/pin.sha256")" "$TOL_DIG  $SUB/mv/tol-moved.json" \
            "the record travels verbatim: the tolerated drift is NOT re-recorded"
  assert_file "$TOL_NEW_SLOT/ignored.json" "the declaration travelled"
  assert_eq "$(cat "$TOL_NEW_SLOT/ignored.json")" '[["model"]]' "byte for byte"
  ANS=""
  run_pinned verify "$SUB/mv/tol-moved.json"
  assert_exit "$RC" 5 "and the moved record answers 5 at its new path, as before the move"
else
  say "S14: tolerated-drift cases SKIPPED (no jq in the trusted PATH)"
fi

# --- repo records ----------------------------------------------------------
if [ "$GIT_OK" -eq 1 ]; then
  mgit() { # repo git-args... -- scrubbed git against ONE named fixture repo
    local r="$1"; shift
    env -i PATH="$PATH" HOME=/var/empty \
      GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
      git -C "$r" -c init.defaultBranch=main -c user.name=harness \
      -c user.email=harness@example.invalid -c commit.gpgsign=false \
      -c core.hooksPath=/dev/null "$@"
  }
  MVR_OLD="$FIX/mvrepo-old"; MVR_NEW="$FIX/mvrepo-new"; MVR_OTHER="$FIX/mvrepo-other"
  mkdir -p "$MVR_OLD" "$MVR_OTHER"
  mgit "$MVR_OLD" init -q
  printf 'r1\n' > "$MVR_OLD/f"; mgit "$MVR_OLD" add f; mgit "$MVR_OLD" commit -q -m r1
  mgit "$MVR_OLD" tag v1
  MVR_HASH="$(mgit "$MVR_OLD" rev-parse 'HEAD^{commit}')"
  mgit "$MVR_OTHER" init -q
  printf 'o1\n' > "$MVR_OTHER/f"; mgit "$MVR_OTHER" add f; mgit "$MVR_OTHER" commit -q -m o1
  ANS='
y
'
  run_pinned review "$MVR_OLD" --tag v1
  assert_exit "$RC" 0 "fixture: the repo record exists, with a declared tag"
  # LABEL OWNERSHIP: `git HEAD:` is the live checkout's fact and `pinned:` is
  # the record's; a tag-selected revision is neither -- it is the candidate
  # under ceremony, and says so.
  assert_contains "$OUT" "candidate:" "a tag-selected revision is labelled candidate"
  assert_missing "$OUT" "commit:" "and no longer wears the ownerless commit label"
  MVR_OLD_SLOT="$(slot_of "$MVR_OLD")"
  MVR_NEW_SLOT="$(slot_of "$MVR_NEW")"
  # A per-slot signers override, the one annotation that lives in a subdir.
  mkdir -p "$MVR_OLD_SLOT/signers"
  printf 'harness@example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n' \
    > "$MVR_OLD_SLOT/signers/allowed_signers"
  chmod 640 "$MVR_OLD_SLOT/signers/allowed_signers"

  # Refusals first -- they need the record still keyed to the old path.
  mv "$MVR_OLD" "$MVR_NEW"
  ANS=""
  run_pinned mv "$MVR_OLD" "$MVR_OTHER"
  assert_exit "$RC" 1 "a repo record refuses a work tree whose object store lacks the pinned rev"
  assert_contains "$OUT" "not the repository the record names" "the refusal names the reason"
  mkdir -p "$MVR_NEW/subdir"
  run_pinned mv "$MVR_OLD" "$MVR_NEW/subdir"
  assert_exit "$RC" 1 "a repo record refuses a path that is not the work-tree root"
  assert_contains "$OUT" "not the work-tree root" "through the shared resolver"
  run_pinned mv "$MVR_OLD" "$SUB/mv/live-copy.txt"
  assert_exit "$RC" 1 "a repo record refuses a non-directory new path"
  assert_contains "$OUT" "moves to a work tree" "and says what a repo record moves to"
  assert_absent "$MVR_OLD_SLOT/tombstone" "no refusal wrote anything"

  ANS='y
'
  run_pinned mv "$MVR_OLD" "$MVR_NEW"
  assert_exit "$RC" 0 "a repo record moves to the work tree that holds its rev"
  assert_eq "$(cat "$MVR_NEW_SLOT/rev.git")" "$MVR_HASH" "the rev travels verbatim"
  assert_eq "$(count_state "$MVR_NEW_SLOT")" 1 "the new slot holds exactly one state file"
  assert_eq "$(cat "$MVR_NEW_SLOT/tag")" "v1" "the declared tag travelled"
  assert_file "$MVR_NEW_SLOT/signers/allowed_signers" "the per-slot signers travelled"
  assert_contains "$MVR_NEW_SLOT/signers/allowed_signers" "harness@example.invalid" "with their content"
  assert_file "$MVR_OLD_SLOT/tombstone" "the old key is tombstoned"
  assert_contains "$MVR_OLD_SLOT/tombstone" "moved to $MVR_NEW" "naming where the record went"
  assert_absent "$MVR_OLD_SLOT/tag" "the old slot's declared name went with the record"
  assert_absent "$MVR_OLD_SLOT/signers" "and so did its signers"
  ANS=""
  run_pinned status "$MVR_NEW"
  assert_exit "$RC" 0 "status at the new path exits 0"
  assert_contains "$OUT" "HEAD is approved" "and reports the moved record as approved"
else
  say "S14: repo cases SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S15: add (checkout -> pin -> flake input)"
# ---------------------------------------------------------------------------
# add composes three idempotent parts, and the assertions below are mostly
# about the SEAMS between them: which part is skipped when it is already
# satisfied, which refusals arrive before a ceremony is ever offered, and
# what the flake looks like afterwards -- including the placeholder dance
# (an all-zero rev goes in, the approved rev replaces it), whose whole point
# is that an interrupted add cannot leave a fetchable-but-unapproved input.
#
# The pin ceremony itself is do_approve's and is covered by S8/S8b; here it
# is driven only far enough to produce the record part 3 reads.

# --- the argument grammar, unit-driven ------------------------------------
run_probe add_input_name "/Users/x/Projects/pinned"
assert_eq "$POUT" "pinned" "name: a local path is its last component"
run_probe add_input_name "https://example.invalid/o/repo.git"
assert_eq "$POUT" "repo" "name: a url loses its .git suffix"
run_probe add_input_name "git@example.invalid:owner/thing.git"
assert_eq "$POUT" "thing" "name: an scp-like remote resolves the same way"
run_probe add_input_name "ssh://git@example.invalid/a/b/"
assert_eq "$POUT" "b" "name: a trailing slash names the same repo"
run_probe add_input_name "git@example.invalid:solo.git"
assert_eq "$POUT" "solo" "name: an scp-like remote with no slash still resolves"

run_probe validate_input_name "good_name-1"
assert_exit "$RC" 0 "name grammar: letters, digits, underscore and dash pass"
run_probe validate_input_name "9lives"
assert_exit "$RC" 1 "name grammar: a leading digit is refused"
run_probe validate_input_name "has.dot"
assert_exit "$RC" 1 "name grammar: a dot is refused (it would split a nix attr path)"
run_probe validate_input_name "has/slash"
assert_exit "$RC" 1 "name grammar: a slash is refused (it becomes a directory name)"
run_probe validate_input_name ""
assert_exit "$RC" 1 "name grammar: the empty name is refused"

run_probe add_arg_kind "$SUB"
assert_eq "$POUT" "path" "classify: an existing directory is a checkout"
run_probe add_arg_kind "https://example.invalid/o/repo.git"
assert_eq "$POUT" "url" "classify: a scheme url is cloned"
run_probe add_arg_kind "git@example.invalid:o/repo.git"
assert_eq "$POUT" "url" "classify: an scp-like remote is cloned"
run_probe add_arg_kind "$SUB/no-such-dir"
assert_exit "$RC" 1 "classify: neither reading applies -> refusal"
assert_contains "$ERRF" "neither an existing directory nor a clonable url" \
  "the refusal names both readings"
run_probe add_arg_kind "$SUB/a:b"
assert_exit "$RC" 1 "classify: a colon after a slash is not a host"

if printf '  nixpkgs.url = "github:NixOS/nixpkgs";\n' | "$PROBE" flake_declares_input nixpkgs; then
  ok "input detection: <name>.url = ... reads as a declaration"
else
  fail "input detection: <name>.url = ... reads as a declaration"
fi
if printf '  inputs.nixpkgs.url = "github:NixOS/nixpkgs";\n' | "$PROBE" flake_declares_input nixpkgs; then
  ok "input detection: inputs.<name>.url = ... reads as a declaration"
else
  fail "input detection: inputs.<name>.url = ... reads as a declaration"
fi
if printf '  nixpkgs = {\n    url = "x";\n  };\n' | "$PROBE" flake_declares_input nixpkgs; then
  ok "input detection: <name> = { ... } reads as a declaration"
else
  fail "input detection: <name> = { ... } reads as a declaration"
fi
if printf '  outputs = { self, nixpkgs }: { };\n' | "$PROBE" flake_declares_input nixpkgs; then
  fail "input detection: an outputs argument is not a declaration"
else
  ok "input detection: an outputs argument is not a declaration"
fi

if [ "$GIT_OK" -eq 1 ]; then
  ZEROS=0000000000000000000000000000000000000000
  new_flake() { # path -- a fixture system flake with the inputs anchor
    cat > "$1" <<'EOF'
{
  description = "harness fixture system flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: { };
}
EOF
  }

  # A repo whose COMMITTED flake.nix declares nixpkgs, plus a work tree that
  # says otherwise: the block must follow the approved tree, never the
  # editable one.
  ADD_A="$FIX/add-a"
  mkdir -p "$ADD_A"
  bgit "$ADD_A" init -q
  cat > "$ADD_A/flake.nix" <<'EOF'
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: { };
}
EOF
  bgit "$ADD_A" add flake.nix; bgit "$ADD_A" commit -q -m "flake with nixpkgs"
  A_REV="$(bgit "$ADD_A" rev-parse 'HEAD^{commit}')"
  printf '{ outputs = { self }: { }; }\n' > "$ADD_A/flake.nix"   # dirty, not approved

  FL_A="$FIX/add-flake-a.nix"
  new_flake "$FL_A"
  ANS='
y
y
'
  run_pinned add "$ADD_A" --flake "$FL_A"
  assert_exit "$RC" 0 "add on a fresh repo exits 0"
  assert_contains "$OUT" "used in place" "part 1 says the checkout is used as it stands"
  assert_contains "$OUT" "full tree at" "part 2 is do_approve's own first-approval review"
  assert_eq "$(cat "$(slot_of "$ADD_A")/rev.git")" "$A_REV" "the ceremony pinned the repo"
  assert_contains "$OUT" "inputs.nixpkgs.follows" \
    "the block follows nixpkgs, read from the APPROVED tree (the work tree says otherwise)"
  assert_contains "$FL_A" "add-a = {" "the input landed under its derived name"
  assert_contains "$FL_A" "git+file://$ADD_A?ref=refs/heads/main&rev=$A_REV" \
    "the input url carries the approved rev and the checkout's branch"
  assert_missing "$FL_A" "rev=$ZEROS" "the placeholder rev is gone"
  assert_contains "$FL_A" "  inputs = {" "the anchor line survives"
  assert_eq "$(grep -c 'add-a = {' "$FL_A")" 1 "the block was inserted exactly once"
  # Insertion point: the block's first line is the one right after the anchor.
  assert_eq "$(grep -A1 '^  inputs = {$' "$FL_A" | tail -n1)" "    add-a = {" \
    "the block sits immediately after the inputs anchor"
  assert_contains "$OUT" "Consuming it stays yours" \
    "the close says the consuming edit is the human's"
  assert_contains "$OUT" "pinned deploy" "and names the verb that builds from it"

  # Idempotence: every part already satisfied costs nothing and asks nothing.
  FL_A_BEFORE="$(digest_of "$FL_A")"
  ANS=""
  run_pinned add "$ADD_A" --flake "$FL_A"
  assert_exit "$RC" 0 "a second add is a no-op that exits 0"
  assert_contains "$OUT" "nothing to do" "and says so"
  assert_contains "$OUT" "already approved" "the pin is reported, not re-asked"
  assert_contains "$OUT" "already names this repo" "and so is the input"
  assert_eq "$(digest_of "$FL_A")" "$FL_A_BEFORE" "the flake is untouched"

  # The elevation gate's --yes rides through in the argv the display showed
  # (S8i), so the root side must take it as the no-op it is rather than turn
  # the documented non-interactive path into a usage error after the
  # authentication.
  ANS=""
  run_pinned add "$ADD_A" --flake "$FL_A" --yes
  assert_exit "$RC" 0 "the root side adds with --yes in its argv"
  assert_contains "$OUT" "nothing to do" "reaching the same no-op"
  assert_missing "$OUT" "usage: pinned" "--yes is not a usage error there"

  # An add interrupted between its insert and its rev sync leaves the
  # placeholder behind. The rerun does not re-edit the flake -- syncing revs
  # is deploy's one job -- but it must not report that state as "nothing to
  # do" either. Simulated by putting the placeholder back.
  sed_i_fix() { if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi; }
  sed_i_fix -e "s/rev=$A_REV/rev=$ZEROS/" "$FL_A"
  ANS=""
  run_pinned add "$ADD_A" --flake "$FL_A"
  assert_exit "$RC" 0 "a flake still holding the placeholder exits 0"
  assert_contains "$OUT" "does not name the approved rev yet" "the unsynced rev is named"
  assert_contains "$OUT" "pinned deploy" "and the verb that syncs it is pointed at"
  assert_contains "$FL_A" "rev=$ZEROS" "add does not do deploy's job behind its back"
  sed_i_fix -e "s/rev=$ZEROS/rev=$A_REV/" "$FL_A"

  # A name already spoken for, by another path, is the human's to resolve.
  ADD_B="$FIX/add-b"
  mkdir -p "$ADD_B"
  bgit "$ADD_B" init -q; printf 'b\n' > "$ADD_B/f"; bgit "$ADD_B" add f; bgit "$ADD_B" commit -q -m b
  ANS=""
  run_pinned add "$ADD_B" --input add-a --flake "$FL_A"
  assert_exit "$RC" 1 "a name collision is refused"
  assert_contains "$OUT" "already declares an input named 'add-a'" "the refusal names the collision"
  assert_eq "$(digest_of "$FL_A")" "$FL_A_BEFORE" "and the flake is untouched"
  assert_absent "$(slot_of "$ADD_B")/rev.git" "the collision refused BEFORE any ceremony"

  # A repo with no nixpkgs input gets no follows line -- and a decline leaves
  # the flake byte-identical.
  FL_B="$FIX/add-flake-b.nix"
  new_flake "$FL_B"
  FL_B_BEFORE="$(digest_of "$FL_B")"
  ANS='
y
n
'
  run_pinned add "$ADD_B" --flake "$FL_B"
  assert_exit "$RC" 2 "declining the input block exits 2"
  assert_contains "$OUT" "aborted; flake unchanged" "the decline names what stayed put"
  assert_eq "$(digest_of "$FL_B")" "$FL_B_BEFORE" "the flake is byte-identical after a decline"
  assert_missing "$OUT" "inputs.nixpkgs.follows" \
    "a repo with no flake.nix gets no follows line"
  assert_contains "$OUT" "no flake.nix" "and the note says why nix will refuse it"
  # The pin the declined run recorded is real trust: it stays.
  assert_file "$(slot_of "$ADD_B")/rev.git" "the pin the ceremony wrote survives the decline"

  # Rerunning after the decline: the pin is skipped, only the input is asked
  # for -- one y, not two.
  ANS='y
'
  run_pinned add "$ADD_B" --flake "$FL_B"
  assert_exit "$RC" 0 "the rerun needs only the input confirmation"
  assert_contains "$OUT" "no ceremony" "the recorded pin is not re-reviewed"
  assert_contains "$FL_B" "rev=$(bgit "$ADD_B" rev-parse 'HEAD^{commit}')" \
    "the input carries the pin recorded earlier"

  # A slot that declares a release name pins the input to that ref.
  ADD_T="$FIX/add-tagged"
  mkdir -p "$ADD_T"
  bgit "$ADD_T" init -q; printf 't\n' > "$ADD_T/f"; bgit "$ADD_T" add f; bgit "$ADD_T" commit -q -m t
  bgit "$ADD_T" tag v3
  T_REV="$(bgit "$ADD_T" rev-parse 'HEAD^{commit}')"
  seed_state "$ADD_T" rev.git "$T_REV"
  printf 'v3\n' > "$(slot_of "$ADD_T")/tag"
  FL_T="$FIX/add-flake-t.nix"
  new_flake "$FL_T"
  ANS='y
'
  run_pinned add "$ADD_T" --flake "$FL_T"
  assert_exit "$RC" 0 "a tag-declared slot adds fine"
  assert_contains "$FL_T" "?ref=refs/tags/v3&rev=$T_REV" \
    "the input's ref names the declared release, not a branch"

  # A detached HEAD with no declared name leaves nothing honest to write.
  ADD_D="$FIX/add-detached"
  mkdir -p "$ADD_D"
  bgit "$ADD_D" init -q; printf 'd1\n' > "$ADD_D/f"; bgit "$ADD_D" add f; bgit "$ADD_D" commit -q -m d1
  printf 'd2\n' > "$ADD_D/f"; bgit "$ADD_D" commit -q -am d2
  bgit "$ADD_D" checkout -q --detach HEAD
  seed_state "$ADD_D" rev.git "$(bgit "$ADD_D" rev-parse 'HEAD^{commit}')"
  FL_D="$FIX/add-flake-d.nix"
  new_flake "$FL_D"
  FL_D_BEFORE="$(digest_of "$FL_D")"
  ANS=""
  run_pinned add "$ADD_D" --flake "$FL_D"
  assert_exit "$RC" 1 "a detached HEAD with no declared tag is refused"
  assert_contains "$OUT" "detached HEAD" "the refusal names the state"
  assert_contains "$OUT" "an input needs a ref" "and why an input cannot be written"
  assert_eq "$(digest_of "$FL_D")" "$FL_D_BEFORE" "the flake is untouched"

  # No anchor, no guessing: the block is printed for by-hand placement.
  FL_N="$FIX/add-flake-noanchor.nix"
  printf '{\n  inputs.nixpkgs.url = "github:NixOS/nixpkgs";\n}\n' > "$FL_N"
  FL_N_BEFORE="$(digest_of "$FL_N")"
  ANS=""
  run_pinned add "$ADD_T" --flake "$FL_N"
  assert_exit "$RC" 1 "a flake without the inputs anchor is refused"
  assert_contains "$OUT" "refusing to guess where an input belongs" "the refusal says why"
  assert_contains "$OUT" "rev=$ZEROS" "and prints the block, placeholder and all, to place by hand"
  assert_eq "$(digest_of "$FL_N")" "$FL_N_BEFORE" "the flake is untouched"

  # A subdirectory is not a repo: resolve_repo's rule holds here too.
  mkdir -p "$ADD_B/sub"
  ANS=""
  run_pinned add "$ADD_B/sub" --flake "$FL_B"
  assert_exit "$RC" 1 "a subdirectory argument is refused"
  assert_contains "$OUT" "not the work-tree root" "with the work-tree rule named"

  # --- the url case: a real clone into the shared tree ---------------------
  # file:// keeps it local while still going through git's transport layer
  # (a plain path would hardlink instead of fetching).
  ADD_SRC="$FIX/add-src"
  mkdir -p "$ADD_SRC"
  bgit "$ADD_SRC" init -q
  printf '{\n  inputs.nixpkgs.url = "github:NixOS/nixpkgs";\n  outputs = { self, nixpkgs }: { };\n}\n' > "$ADD_SRC/flake.nix"
  bgit "$ADD_SRC" add flake.nix; bgit "$ADD_SRC" commit -q -m "src flake"
  SRC_URL="file://$ADD_SRC"
  FL_U="$FIX/add-flake-u.nix"
  new_flake "$FL_U"
  ANS='
y
y
'
  run_pinned add "$SRC_URL" --input cloned --flake "$FL_U"
  assert_exit "$RC" 0 "add from a url exits 0"
  assert_contains "$OUT" "cloning:" "the clone is announced before it runs"
  assert_file "$PINNED_CLONES/cloned/.git/config" "the clone landed in the shared tree"
  # git lowercases the key when it writes it -- the value is what matters.
  assert_contains "$PINNED_CLONES/cloned/.git/config" "sharedrepository = group" \
    "the clone is group-shared at init time"
  assert_contains "$FL_U" "cloned = {" "the input took the --input name"
  assert_contains "$FL_U" "git+file://$PINNED_CLONES/cloned?ref=" \
    "the input names the clone in the shared tree, not the url"
  assert_missing "$FL_U" "rev=$ZEROS" "the placeholder was synced away"
  assert_eq "$(cat "$(slot_of "$PINNED_CLONES/cloned")/rev.git")" \
    "$(bgit "$ADD_SRC" rev-parse 'HEAD^{commit}')" "the clone was pinned at the source's commit"

  # Second run: the destination is reused because its origin matches.
  ANS=""
  run_pinned add "$SRC_URL" --input cloned --flake "$FL_U"
  assert_exit "$RC" 0 "a second url add is a no-op"
  assert_contains "$OUT" "origin matches, nothing fetched" "the existing clone is reused"
  assert_contains "$OUT" "nothing to do" "and every part is already satisfied"

  # A destination holding somebody else's clone is never adopted.
  ANS=""
  run_pinned add "file://$ADD_B" --input cloned --flake "$FL_U"
  assert_exit "$RC" 1 "a clone of another remote at the destination is refused"
  assert_contains "$OUT" "holds a clone of another remote" "the refusal names the mismatch"
  assert_contains "$OUT" "you asked for: file://$ADD_B" "and both urls"

  # And neither is a directory that is no repository of its own. Git's
  # discovery walks UP, so a plain directory inside another checkout answers
  # for THAT checkout -- the clone tree is made a repository here so the
  # fall-through is deterministic rather than a property of $TMPDIR.
  mkdir -p "$PINNED_CLONES/squatter"
  bgit "$PINNED_CLONES" init -q
  ANS=""
  run_pinned add "file://$ADD_B" --input squatter --flake "$FL_U"
  assert_exit "$RC" 1 "a non-repository at the destination is refused"
  assert_contains "$OUT" "is not a git repository of its own" "the refusal says what it found"
  rm -rf "$PINNED_CLONES/.git"

  # Bad argv dies before anything is created.
  ANS=""
  run_pinned add "$ADD_B" --input "bad name" --flake "$FL_B"
  assert_exit "$RC" 1 "an out-of-grammar --input is refused"
  assert_contains "$OUT" "outside the name grammar" "the refusal names the grammar"
  ANS=""
  run_pinned add "$ADD_B" "$ADD_A" --flake "$FL_B"
  assert_exit "$RC" 1 "two positionals are refused"
  assert_contains "$OUT" "add takes one repo or url" "with the one-argument rule named"
  ANS=""
  run_pinned add --flake "$FL_B"
  assert_exit "$RC" 1 "add with no argument is usage"
  ANS=""
  run_pinned add "$ADD_B" --flake "$FIX/no-such-flake.nix"
  assert_exit "$RC" 1 "an unreadable flake is refused"
  assert_contains "$OUT" "cannot read" "naming the file it could not read"
else
  say "S15: SKIPPED (no git fixture)"
fi

# ---------------------------------------------------------------------------
say "S16: the frozen syslog vocabulary"
# ---------------------------------------------------------------------------
# The audit log is append-only, so its action tags are FROZEN NOUNS, not UI
# copy: a tag renamed to follow a verb splits the history into eras that no
# single query spans. The log already carries one such scar (the display verb
# logged review before 2026-08-13 and show after), which is why the ceremony
# tags stayed approve/approve-file through the approve->review rename -- see
# the comment above log_action in the script. This reads the set straight
# from the source's call sites: a new or renamed tag fails HERE, and the fix
# for a legitimate addition is editing the list below, a diff that says out
# loud that the log's vocabulary is changing.
LOG_TAGS="$(grep -v '^[[:space:]]*#' "$SRC" \
  | grep -o 'log_action "\{0,1\}[A-Za-z][A-Za-z0-9$_-]*' \
  | sed 's/^log_action "\{0,1\}//' | LC_ALL=C sort -u | tr '\n' ' ')"
assert_eq "$LOG_TAGS" \
  'add approve approve-file ignorable-$sub mv setup show sign signer-add signer-remove tombstone ' \
  "the syslog action tags are exactly the frozen set (see log_action's comment)"

# ---------------------------------------------------------------------------
say "S17: setup's interpreter guard"
# ---------------------------------------------------------------------------
# setup writes a sudoers Digest_Spec over the INSTALLED script's bytes -- and
# sudo hands the root process the caller's PATH, so an `env` shebang on that
# installed copy would let the invoker's environment choose which bash runs
# as root, with the digest none the wiser. The script's own line 1 names
# /bin/bash, so a verbatim install is already safe; verify_interpreter_pin is
# the belt-and-braces check for an install that predates the pinning or was
# hand-edited, and it refuses at provisioning time. It is driven through the
# PROBE here (setup itself needs real root, see the coverage gaps at the
# top), so these cases exercise the guard's own logic; the last assertion
# pins its position in do_setup, which is the half the probe cannot reach.
INTERP="$FIX/interp"
mkdir -p "$INTERP"

# A stand-in for a pinned interpreter. The stub widens the owner allowlist to
# the harness user, so a 755 fixture file is what verify_root_owned_path calls
# root-owned here; the MODE half of the check stays real (see the 777 case).
GOOD_BASH="$INTERP/bin-bash"
: > "$GOOD_BASH"; chmod 755 "$GOOD_BASH"
LOOSE_BASH="$INTERP/loose-bash"
: > "$LOOSE_BASH"; chmod 777 "$LOOSE_BASH"

write_shebang() { # name first-line -> path of a fixture "install"
  printf '%s\ntrue\n' "$2" > "$INTERP/$1"
  printf '%s\n' "$INTERP/$1"
}

run_probe verify_interpreter_pin "$(write_shebang env.sh '#!/usr/bin/env bash')"
assert_exit "$RC" 1 "env shebang: refused"
assert_contains "$ERRF" "runs under an env shebang: #!/usr/bin/env bash" \
  "env shebang: says what it found"
assert_contains "$ERRF" "The sudoers digest pins this script's bytes, not its interpreter, and" \
  "env shebang: says why the digest does not cover it"
assert_contains "$ERRF" "Reinstall from a current checkout -- its first line already names an" \
  "env shebang: says how to fix it"

# Any path ending in /env is the same PATH-search delegator, wherever it sits.
run_probe verify_interpreter_pin "$(write_shebang env2.sh '#!/run/current-system/sw/bin/env bash')"
assert_exit "$RC" 1 "env under another prefix: refused"
assert_contains "$ERRF" "runs under an env shebang" "env under another prefix: same refusal"

run_probe verify_interpreter_pin "$(write_shebang rel.sh '#!bash')"
assert_exit "$RC" 1 "relative interpreter: refused"
assert_contains "$ERRF" "names a relative interpreter: #!bash" \
  "relative interpreter: says what it found"

run_probe verify_interpreter_pin "$(write_shebang none.sh 'no shebang at all')"
assert_exit "$RC" 1 "no shebang: refused"
assert_contains "$ERRF" "has no shebang" "no shebang: says what it found"

printf '' > "$INTERP/empty.sh"
run_probe verify_interpreter_pin "$INTERP/empty.sh"
assert_exit "$RC" 1 "empty file: refused"
assert_contains "$ERRF" "has no shebang" "empty file: refused as shebang-less"

run_probe verify_interpreter_pin "$INTERP/no-such-file.sh"
assert_exit "$RC" 1 "missing install target: refused"
assert_contains "$ERRF" "is not a regular file" "missing install target: says what it found"

# The interpreter must survive the ownership walk too: a world-writable one
# is swappable, so pinning its path buys nothing.
run_probe verify_interpreter_pin "$(write_shebang loose.sh "#!$LOOSE_BASH")"
assert_exit "$RC" 1 "world-writable interpreter: refused"
assert_contains "$ERRF" "has mode 777" "world-writable interpreter: the mode check fired"
assert_contains "$ERRF" "names an interpreter that is not root-owned" \
  "world-writable interpreter: the guard says why it matters"

run_probe verify_interpreter_pin "$(write_shebang gone.sh '#!/nonexistent/bin/bash')"
assert_exit "$RC" 1 "absolute but absent interpreter: refused"
assert_contains "$ERRF" "names an interpreter that is not root-owned" \
  "absent interpreter: fails closed like any unverifiable path"

# The passing shape: absolute, root-owned, no env in sight.
run_probe verify_interpreter_pin "$(write_shebang good.sh "#!$GOOD_BASH")"
assert_exit "$RC" 0 "absolute root-owned interpreter: passes the guard"
assert_eq "$(wc -c <"$ERRF" | tr -d ' ')" "0" "passing install says nothing"

# Shebang parsing is not a substring match: leading blanks and an interpreter
# argument must not change which path is judged.
run_probe verify_interpreter_pin "$(write_shebang good2.sh "#!  $(printf '\t')$GOOD_BASH -e")"
assert_exit "$RC" 0 "leading blanks and an interpreter argument: still passes"

# ...and a path that merely CONTAINS env is not an env shebang.
ENVDIR="$INTERP/envs"
mkdir -p "$ENVDIR"
: > "$ENVDIR/bash"; chmod 755 "$ENVDIR/bash"
run_probe verify_interpreter_pin "$(write_shebang good3.sh "#!$ENVDIR/bash")"
assert_exit "$RC" 0 "an interpreter under a dir named envs: passes (not an env shebang)"

# The call site: the guard must run BEFORE setup computes the digest it would
# pin. A probe cannot reach do_setup (real root), so its position is asserted
# in the source -- moving the guard after the digest would be a silent regression.
GUARD_LINE="$(grep -n '^  verify_interpreter_pin "\$target" || exit 1$' "$SRC" | cut -d: -f1)"
DIGEST_LINE="$(grep -n '^  digest="\$(shasum ' "$SRC" | cut -d: -f1)"
if [ -n "$GUARD_LINE" ] && [ -n "$DIGEST_LINE" ] && [ "$GUARD_LINE" -lt "$DIGEST_LINE" ]; then
  ok "setup runs the interpreter guard before it computes the sudoers digest"
else
  fail "setup runs the interpreter guard before it computes the sudoers digest (guard='$GUARD_LINE' digest='$DIGEST_LINE')"
fi

# ---------------------------------------------------------------------------
say "S18: --version"
# ---------------------------------------------------------------------------
# The version answers about the file itself, so it must not depend on any
# state the verbs below it read -- it is served at the dispatch, and the
# string is the release the tag names.
SRC_VERSION="$(sed -n 's/^PINNED_VERSION="\(.*\)"$/\1/p' "$SRC" | head -n1)"
case "$SRC_VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ok "the declared version is a semver triple ($SRC_VERSION)" ;;
  *) fail "the declared version is a semver triple (got '$SRC_VERSION')" ;;
esac
ANS=""
run_pinned --version
assert_exit "$RC" 0 "--version exits 0"
assert_eq "$(cat "$OUT")" "pinned $SRC_VERSION" "--version prints the constant the script declares"

ANS=""
run_pinned
assert_exit "$RC" 1 "no argv is usage"
assert_contains "$OUT" "--version" "usage lists the flag"

# ---------------------------------------------------------------------------
say ""
if [ "$FAIL" -eq 0 ]; then
  rm -rf "$FIX"
else
  say "fixtures kept for inspection: $FIX"
fi
say "passed=$PASS failed=$FAIL"
exit $(( FAIL > 0 ))
