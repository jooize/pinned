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
#      driven by $ANS
#   6. log_action's `logger -t pinned` -> no-op, so fixture ceremonies never
#      land in the machine's real approval history
# Every anchor is counted in the source BEFORE the sed (see need()), so a
# drifting script aborts the harness loudly instead of silently testing a
# no-op stub. PIN_ROOT and INSTALL_TARGET are honest environment overrides
# the script already supports; nothing here touches /var/db/pinned, /etc, or
# any live system state.
#
# canon_path / encode / decode / write_slot_state are unit-driven through a
# PROBE: the stub truncated before its first action (a pure function library)
# is sourced, then one function is called by name.
#
# KNOWN COVERAGE GAPS (deliberate):
#   - no real sudo, so the self-elevation preview, the sudoers digest pin,
#     `setup`, `migrate` and `deploy` are untested here
#   - signed-tag approval / `signer` / `sign` need an SSH agent and keys
#   - the group-read tier (0750 root:_<user>-pinned) cannot be built without
#     root: the stub always takes ensure_tree's no-group 0700 branch
#   - blake2b/blake3 algorithms are not exercised (sha256 only)
#   - `review`, `slot`, `status <repo>` dirty-tree warnings: only status's
#     approved/never-approved verdicts are covered
#
# S8's first case is a REGRESSION test: a first-ever repo approval (no slot
# dir yet) must succeed. This harness caught it refusing on delivery day --
# the same not-yet-created-slot ancestry defect approve --file had -- and
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

export PIN_ROOT="$FIX/pinroot"
export INSTALL_TARGET="$FIX/no-such-install"

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
need '^  install -d -m 755 -o root -g wheel "\$PIN_ROOT"$'  1 'pin-root install'
need '-o root -g "\$TREE_GRP" '                             4 'slot-tree installs'
need '^  chown -R "root:\$TREE_GRP"'                        1 'tree chown sweep'
need 'chown "root:\$TREE_GRP"'                              4 'record chowns'
need '^  logger -t pinned '                                 1 'audit-log call'
need '</dev/tty'                                           10 'ceremony tty reads'
need '^# ---- setup ---'                                    1 'library cut marker'

sed -e 's/if \[ "\$EUID" -ne 0 \]; then/if false; then/' \
    -e 's/^  \[ "\$EUID" -eq 0 \] ||.*/  :/' \
    -e 's/^  inv="\${SUDO_USER:-}"$/  inv="$(id -un)"/' \
    -e 's/^  \[ -n "\$inv" \] ||.*/  :/' \
    -e "s/^    root:\\*) ;;\$/    root:*|${USERNAME}:*) ;;/" \
    -e 's/^  install -d -m 755 -o root -g wheel "\$PIN_ROOT"$/  install -d -m 755 "$PIN_ROOT"/' \
    -e 's/-o root -g "\$TREE_GRP" //g' \
    -e 's/^\( *\)chown -R "root:\$TREE_GRP".*/\1:/' \
    -e 's/^\( *\)chown "root:\$TREE_GRP".*/\1:/' \
    -e 's/^  logger -t pinned .*/  :/' \
    -e 's#</dev/tty##g' \
    "$SRC" > "$STUB"
chmod 755 "$STUB"

# Post-conditions: the seds actually landed (a silently-unapplied sed would
# turn every ceremony test into a hang or a sudo prompt).
if grep -q '</dev/tty' "$STUB"; then say "STUB SED FAILED: /dev/tty survives"; exit 2; fi
if [ "$(grep -c 'if false; then' "$STUB")" != 2 ]; then say "STUB SED FAILED: elevation gates"; exit 2; fi
if grep -q '^  logger -t pinned ' "$STUB"; then say "STUB SED FAILED: logger survives"; exit 2; fi

# The pure-function library: everything above the first action.
sed '/^# ---- setup ---/,$d' "$STUB" > "$LIB"

cat > "$PROBE" <<EOF
#!/usr/bin/env bash
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
assert_exit "$RC" 12 "pinned but missing -> 12"
assert_contains "$OUT" "pinned but MISSING" "12 names the absence"

printf 'back from the dead\n' > "$SUB/v/risen.txt"
seed_tombstone "$SUB/v/risen.txt"
run_pinned verify "$SUB/v/risen.txt"
assert_exit "$RC" 13 "tombstoned but present -> 13"
assert_contains "$OUT" "retired content resurrected" "13 names the resurrection"

printf 'loose modes\n' > "$SUB/v/loose.txt"
seed_pin "$SUB/v/loose.txt" "$(digest_of "$SUB/v/loose.txt")"
chmod 664 "$SUB/v/loose.txt"
run_pinned verify "$SUB/v/loose.txt"
assert_exit "$RC" 14 "group-writable subject -> 14"
assert_contains "$OUT" "group/other-writable" "14 names the invariant"
chmod 644 "$SUB/v/loose.txt"
run_pinned verify "$SUB/v/loose.txt"
assert_exit "$RC" 0 "remediated mode verifies again"

run_pinned verify "$SUB/v/never/existed/at/all.txt"
assert_exit "$RC" 10 "absent path under a MISSING parent, no slot -> 10 (launch regression)"
assert_contains "$OUT" "no slot" "the missing-parent case still reaches the slot verdict"

# ---------------------------------------------------------------------------
say "S4: approve --file ceremony"
# ---------------------------------------------------------------------------
mkdir -p "$SUB/a"
printf 'first ever\n' > "$SUB/a/first.txt"
FIRST_SLOT="$(slot_of "$SUB/a/first.txt")"
assert_absent "$FIRST_SLOT" "precondition: no slot dir before the first approval"
ANS='y
'
run_pinned approve --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "first-ever approval of an unpinned path succeeds (regression)"
assert_contains "$OUT" "first approval" "ceremony announces the first approval"
assert_contains "$OUT" "pin.sha256" "ceremony names the record it wrote"
assert_file "$FIRST_SLOT/pin.sha256" "record file exists"
assert_eq "$(cat "$FIRST_SLOT/pin.sha256")" \
          "$(digest_of "$SUB/a/first.txt")  $SUB/a/first.txt" \
          "record is '<digest>  <path>'"
assert_eq "$(count_state "$FIRST_SLOT")" 1 "slot holds exactly one state file"
run_pinned verify "$SUB/a/first.txt"
assert_exit "$RC" 0 "the approved file verifies"

ANS=""
run_pinned approve --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "re-approving identical bytes needs no answer"
assert_contains "$OUT" "already approved" "re-approval short-circuits"

printf 'reinstate me\n' > "$SUB/a/reinstated.txt"
seed_tombstone "$SUB/a/reinstated.txt"
REIN_SLOT="$(slot_of "$SUB/a/reinstated.txt")"
ANS='y
'
run_pinned approve --file "$SUB/a/reinstated.txt"
assert_exit "$RC" 0 "approving over a tombstone succeeds"
assert_contains "$OUT" "approving reinstates this path" "ceremony warns it reinstates"
assert_absent "$REIN_SLOT/tombstone" "tombstone is gone after reinstatement"
assert_eq "$(count_state "$REIN_SLOT")" 1 "reinstated slot holds exactly one state file"

printf 'not this time\n' > "$SUB/a/declined.txt"
DECL_SLOT="$(slot_of "$SUB/a/declined.txt")"
ANS='n
'
run_pinned approve --file "$SUB/a/declined.txt"
assert_exit "$RC" 0 "declining exits 0"
assert_contains "$OUT" "declined; record unchanged" "decline is reported"
assert_eq "$(count_state "$DECL_SLOT")" 0 "declining records nothing"

# ---------------------------------------------------------------------------
say "S5: tombstone"
# ---------------------------------------------------------------------------
mkdir -p "$SUB/t"
printf 'still here\n' > "$SUB/t/live.txt"
ANS='y
'
run_pinned approve --file "$SUB/t/live.txt"
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
ANS='y
'
run_pinned approve --file "$SUB/t/wholesale/conf.json"
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
assert_contains "$OUT" "sha256" "list names the declared kind"
assert_missing  "$OUT" "$SUB/l/never-again.txt" "list omits tombstoned slots"

run_pinned list --under "$SUB/l/sub"
assert_exit "$RC" 0 "list --under exits 0"
assert_contains "$OUT" "$SUB/l/sub/plain.txt" "--under keeps paths below the directory"
assert_missing  "$OUT" "$SUB/l/subx/nearmiss.txt" "--under matches at a component boundary (/l/sub is not /l/subx)"
assert_missing  "$OUT" "$SUB/l/bracket[1].conf" "--under filters out unrelated pins"

# ---------------------------------------------------------------------------
say "S8: repo approve"
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
  # refuse every brand-new repo -- the same defect approve --file fixed
  # with its `[ -d "$slot" ]` branch (see S4). The slot dir is deliberately
  # NOT pre-created here: its absence is the case under test.
  ANS='y
'
  run_pinned approve "$REPO_FIX"
  assert_exit "$RC" 0 "first-ever repo approval succeeds (no slot dir pre-created)"
  assert_contains "$OUT" "full tree at" "first approval shows the full tree"
  assert_contains "$OUT" "rev.git" "ceremony names the record it wrote"
  assert_file "$REPO_SLOT/rev.git" "rev.git written"
  assert_eq "$(cat "$REPO_SLOT/rev.git")" "$HEAD_HASH" "rev.git holds the approved commit"
  assert_eq "$(count_state "$REPO_SLOT")" 1 "repo slot holds exactly one state file"

  ANS=""
  run_pinned status "$REPO_FIX"
  assert_exit "$RC" 0 "status exits 0"
  assert_contains "$OUT" "HEAD is approved" "status reports the pin as approved"

  ANS=""
  run_pinned approve "$REPO_FIX"
  assert_exit "$RC" 0 "re-approving the same HEAD needs no answer"
  assert_contains "$OUT" "already pinned" "re-approval short-circuits"

  printf 'second\n' > "$REPO_FIX/file.txt"
  hgit commit -q -am "second commit" >/dev/null
  ANS=""
  run_pinned status "$REPO_FIX"
  assert_exit "$RC" 0 "status after a new commit exits 0"
  assert_contains "$OUT" "HEAD is NOT approved" "status reports drift from the pin"

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
say ""
if [ "$FAIL" -eq 0 ]; then
  rm -rf "$FIX"
else
  say "fixtures kept for inspection: $FIX"
fi
say "passed=$PASS failed=$FAIL"
exit $(( FAIL > 0 ))
