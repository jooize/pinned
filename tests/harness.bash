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
#   - no real sudo, so the self-elevation preview, the sudoers digest pin,
#     `setup` and `deploy` are untested here
#   - signed-tag approval / `signer` / `sign` need an SSH agent and keys
#   - the group-read tier (0750 root:_<user>-pinned) cannot be built without
#     root: the stub always takes ensure_tree's no-group 0700 branch
#   - blake2b/blake3 algorithms are not exercised (sha256 only)
#   - `review` and `status <repo>` dirty-tree warnings: only status's
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

# Fixture paths for the two constants the sed below bakes into the stub. They
# are plain shell variables here -- the harness uses them to build and inspect
# fixture state; exporting them would do nothing, since the stub no longer
# reads the environment for either.
PINNED_ROOT="$FIX/pinroot"
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
need '^PINNED_MACHINE_POLICY=/etc/pinned/ignorable.json$'   1 'machine-policy constant'
need '^  install -d -m 755 -o root -g wheel "\$PINNED_ROOT"$'  1 'pin-root install'
need '-o root -g "\$TREE_GRP" '                             3 'slot-tree installs'
need '^  chown -R "root:\$TREE_GRP"'                        1 'tree chown sweep'
need 'chown "root:\$TREE_GRP"'                              5 'record chowns'
need '^  logger -t pinned '                                 1 'audit-log call'
need '</dev/tty'                                            10 'ceremony tty reads'
need '^# ---- setup ---'                                    1 'library cut marker'

sed -e "s#^PINNED_ROOT=/var/db/pinned\$#PINNED_ROOT='$PINNED_ROOT'#" \
    -e "s#^PINNED_MACHINE_POLICY=/etc/pinned/ignorable.json\$#PINNED_MACHINE_POLICY='$PINNED_MACHINE_POLICY'#" \
    -e 's/if \[ "\$EUID" -ne 0 \]; then/if false; then/' \
    -e 's/^  \[ "\$EUID" -eq 0 \] ||.*/  :/' \
    -e 's/^  inv="\${SUDO_USER:-}"$/  inv="$(id -un)"/' \
    -e 's/^  \[ -n "\$inv" \] ||.*/  :/' \
    -e "s/^    root:\\*) ;;\$/    root:*|${USERNAME}:*) ;;/" \
    -e 's/^  install -d -m 755 -o root -g wheel "\$PINNED_ROOT"$/  install -d -m 755 "$PINNED_ROOT"/' \
    -e 's/-o root -g "\$TREE_GRP" //g' \
    -e 's/^\( *\)chown -R "root:\$TREE_GRP".*/\1:/' \
    -e 's/^\( *\)chown "root:\$TREE_GRP".*/\1:/' \
    -e 's/^  logger -t pinned .*/  :/' \
    -e 's#</dev/tty##g' \
    "$SRC" > "$STUB"
chmod 755 "$STUB"

# Post-conditions: the seds actually landed (a silently-unapplied sed would
# turn every ceremony test into a hang or a sudo prompt).
if grep -q '^PINNED_ROOT=/var/db/pinned$' "$STUB"; then
  say "STUB SED FAILED: the real pin root survives"; exit 2
fi
if grep -q '^PINNED_MACHINE_POLICY=/etc/pinned/ignorable.json$' "$STUB"; then
  say "STUB SED FAILED: the real machine policy path survives"; exit 2
fi
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
run_pinned_split() { # verb args... -- like run_pinned, but stderr stays in \$ERRF
  # `cat` is the one verb with a stdout CONTRACT ("nothing on stdout in any
  # failure case"), which a merged stream cannot test.
  printf '%s' "$ANS" > "$FIX/stdin"
  RC=0
  "$STUB" "$@" <"$FIX/stdin" >"$OUT" 2>"$ERRF" || RC=$?
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
assert_contains "$OUT" "pinned but MISSING" "20 names the absence"

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
# CUSTODY IS OPT-IN. A plain ceremony records a digest and keeps no witness:
# the slot discloses one hash and nothing about the file's content.
assert_absent "$FIRST_SLOT/approved" "a plain approve keeps no stored copy"
assert_missing "$OUT" "(+approved copy)" "and does not claim to have written one"
assert_contains "$OUT" "custody:" "the ceremony states custody in both directions"
assert_contains "$OUT" "no copy is kept" "and says what 'none' means before the confirm"
run_pinned verify "$SUB/a/first.txt"
assert_exit "$RC" 0 "the approved file verifies"

ANS=""
run_pinned approve --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "re-approving identical bytes needs no answer"
assert_contains "$OUT" "already approved" "re-approval short-circuits"

# ADDING custody is a disclosure decision, so the human confirms it: identical
# bytes stop being a no-op the moment --store changes the custody state.
ANS='y
'
run_pinned approve --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "adding --store to a copy-less slot runs"
assert_missing "$OUT" "already approved" "adding custody defeats the no-op short-circuit"
assert_contains "$OUT" "ADDS a stored copy" "the note names the custody delta and its direction"
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
run_pinned approve --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "identical bytes with unchanged custody need no answer"
assert_contains "$OUT" "already approved" "unchanged custody keeps the short-circuit"

# Dropping it is equally a decision, and equally loud -- stated before the
# confirm and again in the result.
ANS='y
'
run_pinned approve --file "$SUB/a/first.txt"
assert_exit "$RC" 0 "re-approving a custody slot without --store runs"
assert_missing "$OUT" "already approved" "dropping custody defeats the no-op short-circuit"
assert_contains "$OUT" "DROPS the slot's stored copy" "the pre-confirm note says the copy is going"
assert_contains "$OUT" "was DROPPED" "the result line says it went"
assert_absent "$FIRST_SLOT/approved" "a plain re-approve drops the stored copy"

# What custody holds is always what the LAST ceremony displayed.
printf 'second draft\n' > "$SUB/a/first.txt"
ANS='y
'
run_pinned approve --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "re-approving changed bytes with --store succeeds"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(digest_of "$SUB/a/first.txt")" \
          "the witness is the newly approved bytes"
printf 'third draft\n' > "$SUB/a/first.txt"
ANS='y
'
run_pinned approve --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "re-approving again with --store succeeds"
assert_missing "$OUT" "custody change" "unchanged custody needs no custody note"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(awk '{print $1}' "$FIRST_SLOT/pin.sha256")" \
          "the refreshed witness re-hashes to the new pin"

# A stored witness that does not re-hash is incoherent state, and the ceremony
# is what verify tells you to run -- so it must not short-circuit away.
printf 'tampered\n' > "$FIRST_SLOT/approved"
chmod 600 "$FIRST_SLOT/approved"
ANS='y
'
run_pinned approve --file "$SUB/a/first.txt" --store
assert_exit "$RC" 0 "re-approving over an incoherent witness runs"
assert_missing "$OUT" "already approved" "a witness that does not re-hash defeats the short-circuit"
assert_contains "$OUT" "does not re-hash to its record" "the note names the incoherence"
assert_eq "$(digest_of "$FIRST_SLOT/approved")" "$(awk '{print $1}' "$FIRST_SLOT/pin.sha256")" \
          "and the ceremony replaces it"

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
say "S8b: batch repo approve (multiple repos, one invocation)"
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
  ANS='y
y
'
  run_pinned approve "$REPO_A" "$REPO_B"
  assert_exit "$RC" 0 "batch approve of two repos exits 0"
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
  ANS='n
y
'
  run_pinned approve "$REPO_A" "$REPO_B"
  assert_exit "$RC" 0 "a mid-batch decline does not abort the batch"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$A_OLD" "declined repo keeps its old pin"
  assert_eq "$(cat "$B_SLOT/rev.git")" "$(bgit "$REPO_B" rev-parse 'HEAD^{commit}')" "later repo still approved"
  assert_contains "$OUT" "1 approved, 1 declined, 0 already pinned" "summary counts the decline"

  # Already-pinned repos are counted, never re-asked: catch repo A up, then
  # run the batch again -- both at their pins, no answer is consumed.
  ANS='y
'
  run_pinned approve "$REPO_A"
  assert_exit "$RC" 0 "catch-up approve of the declined repo"
  ANS=""
  run_pinned approve "$REPO_A" "$REPO_B"
  assert_exit "$RC" 0 "an all-pinned batch exits 0"
  assert_contains "$OUT" "0 approved, 0 declined, 2 already pinned" "summary counts already-pinned repos"

  # SINGLE-repo contract unchanged: already-pinned exits 0 with no summary
  # line; a decline still exits 2.
  ANS=""
  run_pinned approve "$REPO_A"
  assert_exit "$RC" 0 "single already-pinned repo still exits 0"
  assert_missing "$OUT" "declined," "single-repo approve prints no batch summary"
  printf 'a3\n' > "$REPO_A/f"; bgit "$REPO_A" commit -q -am a3
  ANS='n
'
  run_pinned approve "$REPO_A"
  assert_exit "$RC" 2 "a single-repo decline still exits 2"
  assert_contains "$OUT" "aborted; pin unchanged." "single decline keeps its message"

  # Selector and evidence flags bind to one repo; a batch refuses them.
  ANS=""
  run_pinned approve "$REPO_A" "$REPO_B" --tag v1
  assert_exit "$RC" 1 "--tag with two repos is refused"
  assert_contains "$OUT" "bind to one repo" "the refusal names the rule"
  ANS=""
  run_pinned approve "$REPO_A" "$REPO_B" --trust
  assert_exit "$RC" 1 "--trust with two repos is refused"
fi

# ---------------------------------------------------------------------------
say "S8c: upgrade (approve stale flake inputs, then deploy)"
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

  # Dry run: the stale repo is named, no ceremony runs, nothing recorded.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "upgrade --dry-run exits 0"
  assert_contains "$OUT" "will review + approve:" "dry run shows the plan"
  assert_contains "$OUT" "$REPO_A" "the stale repo is named"
  assert_contains "$OUT" "dry run: no ceremonies" "no ceremony in a dry run"
  assert_contains "$OUT" "Dry run -- nothing executed." "deploy stays a preview"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$A_PIN" "dry run records nothing"

  # Full run: the ceremony approves the stale repo (forced batch contract:
  # a summary even for one repo, so a decline could fall through to
  # deploy), then deploy wants to sync the flake and stops at its
  # confirmation gate -- the harness has no tty, so that gate is the
  # no-tty refusal, and no root command ever runs.
  ANS='y
'
  run_pinned upgrade --flake "$FIX/flake.nix"
  assert_exit "$RC" 2 "deploy's confirmation gate aborts with 2"
  assert_eq "$(cat "$A_SLOT/rev.git")" "$(bgit "$REPO_A" rev-parse 'HEAD^{commit}')" "the ceremony pinned the stale repo"
  assert_contains "$OUT" "1 approved, 0 declined, 0 already pinned" "upgrade forces the batch contract for one repo"
  assert_contains "$OUT" "no tty for confirmation" "deploy stops at its confirmation gate"
  assert_contains "$FIX/flake.nix" "rev=$A_PIN" "the flake file was not rewritten"

  # Nothing stale: the second round has no ceremonies to offer.
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "an up-to-date upgrade dry run exits 0"
  assert_contains "$OUT" "nothing to approve" "no stale inputs reported"

  # A tag-declared slot is never plain-approved: it is listed for manual
  # approve --tag and the plain-approve list stays empty. The tag is a
  # REAL one at the approved rev -- deploy's own live-tag cross-check
  # refuses a declared tag it cannot find (a distinct, correct refusal
  # this case is not about).
  printf 'b3\n' > "$REPO_B/f"; bgit "$REPO_B" commit -q -am b3
  bgit "$REPO_B" tag v9 "$B_PIN"
  printf 'v9\n' > "$B_SLOT/tag"
  ANS=""
  run_pinned upgrade --flake "$FIX/flake.nix" --dry-run
  assert_exit "$RC" 0 "a tag-declared stale input does not break upgrade"
  assert_contains "$OUT" "approve --tag by hand" "tag-declared slot routed to manual approval"
  assert_missing "$OUT" "will review + approve:" "no plain-approve list when only tag-declared slots are stale"
  rm -f "$B_SLOT/tag"
  bgit "$REPO_B" tag -d v9 >/dev/null

  # Malformed argv dies before anything runs.
  ANS=""
  run_pinned upgrade --bogus
  assert_exit "$RC" 1 "unknown upgrade option is usage"
else
  say "S8c: SKIPPED (no git fixture or no rebuild tool)"
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
ANS='y
'
run_pinned approve --file "$SUB/ig/nocopy.json" --ignore-json-key model --ignore-json-key effortLevel
assert_exit "$RC" 0 "approve with --ignore-json-key succeeds"
assert_contains "$OUT" "ignored:" "ceremony displays the proposed ignored keys"
assert_contains "$OUT" "model, effortLevel" "ceremony names them before the confirm"
assert_contains "$OUT" "may drift without re-approval" "ceremony states what ignoring means"
assert_contains "$OUT" "model -- user policy, everywhere" "ceremony shows each key's grant provenance"
assert_contains "$OUT" "no copy is kept" "ceremony states the custody consequence"
assert_file "$(slot_file_of "$SUB/ig/nocopy.json" ignored.json)" "ignored.json recorded"
assert_eq "$(cat "$(slot_file_of "$SUB/ig/nocopy.json" ignored.json)")" '[["model"],["effortLevel"]]' \
          "ignored.json holds the jq path array, in declaration order"
assert_absent "$(slot_file_of "$SUB/ig/nocopy.json" approved)" \
              "a declaration alone keeps no witness -- custody is opt-in"

# --store is what keeps the bytes, and it keeps exactly the approved ones.
printf '{\n  "model": "opus",\n  "effortLevel": "high",\n  "permissions": {"deny": ["Bash"]}\n}\n' > "$SUB/ig/copy.json"
COPY_SLOT="$(slot_of "$SUB/ig/copy.json")"
ANS='y
'
run_pinned approve --file "$SUB/ig/copy.json" --ignore-json-key model --store
assert_exit "$RC" 0 "approve with a declaration AND --store succeeds"
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
assert_contains "$OUT" "differences remain OUTSIDE" "the refusal says where the difference is"

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
assert_contains "$OUT" "DUPLICATE object keys" "the refusal names the duplication"

# A non-JSON file simply never parses, so it always falls back to strict.
printf 'container\n' > "$SUB/ig/lane"
ANS='y
'
run_pinned approve --file "$SUB/ig/lane" --ignore-json-key model --store
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
ANS='y
'
run_pinned approve --file "$SUB/ig/bad.json" --ignore-json-key model
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
# plain approve clears the declaration and drops the stored witness together.
printf '{"model": "opus", "keep": 1}\n' > "$SUB/ig/clear.json"
CLEAR_SLOT="$(slot_of "$SUB/ig/clear.json")"
ANS='y
'
run_pinned approve --file "$SUB/ig/clear.json" --ignore-json-key model --store
assert_exit "$RC" 0 "fixture: clear.json approved with a declaration + stored copy"
ANS='y
'
run_pinned approve --file "$SUB/ig/clear.json"
assert_exit "$RC" 0 "re-approving identical bytes without a declaration still runs"
assert_missing  "$OUT" "already approved" "a changed declaration defeats the no-op short-circuit"
assert_contains "$OUT" "clearing the ignored keys" "the ceremony says the tolerance is being withdrawn"
assert_contains "$OUT" "DROPS the slot's stored copy" "and that custody is going with it"
assert_absent "$CLEAR_SLOT/ignored.json" "a plain approve clears the declaration"
assert_absent "$CLEAR_SLOT/approved" "a plain approve drops the stored copy"
printf '{"model": "sonnet", "keep": 1}\n' > "$SUB/ig/clear.json"
run_pinned verify "$SUB/ig/clear.json"
assert_exit "$RC" 11 "after clearing, the same drift is a plain mismatch again"

# Tombstoning retires the extras with the record.
printf '{"model": "opus"}\n' > "$SUB/ig/doomed.json"
DOOM_SLOT="$(slot_of "$SUB/ig/doomed.json")"
ANS='y
'
run_pinned approve --file "$SUB/ig/doomed.json" --ignore-json-key model --store
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
assert_contains "$OUT" "ignored: model" "list annotates a slot that declares ignored keys"
assert_contains "$OUT" "$SUB/ig/nocopy.json" "list still prints the parseable row"
ANS=""
run_pinned status "$SUB/ig/nocopy.json"
assert_exit "$RC" 0 "status exits 0"
assert_contains "$OUT" "model, effortLevel" "status reports the declared keys"
assert_contains "$OUT" "re-approve with --store" "status says how a copy-less slot gets custody"
run_pinned status "$SUB/ig/copy.json"
assert_contains "$OUT" "live file DIFFERS" "status agrees with verify on a real mismatch"

# Argument surface.
ANS=""
run_pinned approve --file "$SUB/ig/nocopy.json" --ignore-json-key 'permissions.deny[0]'
assert_exit "$RC" 1 "an out-of-grammar --ignore-json-key is refused up front"
assert_contains "$OUT" "outside the key grammar" "the refusal names the grammar"
# --store COMBINES FREELY. Custody serves the tolerant comparison, but also
# archives what was approved and feeds pinned cat, so it means something on a
# ceremony that declares nothing -- the old "--store applies to a ceremony
# that declares --ignore-json-key" pairing refusal must stay gone.
ANS='n
'
run_pinned approve --file "$SUB/ig/nocopy.json" --store
assert_exit "$RC" 0 "--store on a ceremony that declares NO ignored keys is accepted"
assert_missing "$OUT" "--store applies to a ceremony" "the retired pairing refusal does not come back"
assert_contains "$OUT" "kept in the slot" "custody stands on its own in the display"
# It is still the FILE ceremony's flag: a repo approve has no bytes to keep.
ANS=""
run_pinned approve "$SUB" --store
assert_exit "$RC" 1 "--store outside the --file ceremony is refused"
assert_contains "$OUT" "--store applies to the --file ceremony only" "the refusal names the ceremony"
run_pinned approve --ignore-json-key model --file "$SUB/ig/nocopy.json"
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
ANS='y
'
run_pinned approve --file "$SUB/pol/in/s.json" --ignore-json-key model
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
assert_contains "$OUT" "ABSOLUTE" "the refusal names the requirement"
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
ANS='y
'
run_pinned approve --file "$SUB/pol/in/s.json" --ignore-json-key model --store
assert_exit "$RC" 0 "a granted key in scope approves"
assert_contains "$OUT" "model -- user policy, under $SUB/pol/in" "provenance names the scope"
ANS='y
'
run_pinned approve --file "$SUB/pol/inx/s.json" --ignore-json-key model
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
ANS='y
'
run_pinned approve --file "$SUB/pol/in/s.json" --ignore-json-key model
assert_exit "$RC" 1 "an unscoped user grant is NOT covered by a scoped machine entry"
assert_contains "$OUT" "does not grant these keys" "the intersection refuses it"

# Narrower than the machine scope is inside it; equal is inside it too.
seed_policy_user "[{\"path\":[\"model\"],\"under\":\"$SUB/pol/in/deeper\"}]"
mkdir -p "$SUB/pol/in/deeper"
printf '%s\n' "$JSON_IN" > "$SUB/pol/in/deeper/s.json"
ANS='y
'
run_pinned approve --file "$SUB/pol/in/deeper/s.json" --ignore-json-key model --store
assert_exit "$RC" 0 "a user scope BELOW the machine scope survives the intersection"
assert_contains "$OUT" "under $SUB/pol/in/deeper" "provenance names the narrower scope"

# An unusable tier grants nothing -- on either rung, at both ends.
seed_policy_machine '{"path": ["model"]}'
ANS='y
'
run_pinned approve --file "$SUB/pol/in/deeper/s.json" --ignore-json-key model
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
ANS='y
'
run_pinned approve --file "$SUB/pol/heal.json"
assert_exit "$RC" 0 "a root ceremony runs with a legacy signers/ dir present"
assert_contains "$OUT" "moved allowed_signers into the policy dir" "the move is announced"
assert_file "$PINNED_ROOT/$USERNAME/policy/allowed_signers" "allowed_signers now lives in policy/"
assert_eq "$(cat "$PINNED_ROOT/$USERNAME/policy/allowed_signers")" "harness ssh-ed25519 AAAAfake" \
          "the moved file keeps its content"
assert_absent "$PINNED_ROOT/$USERNAME/signers" "the emptied legacy dir is removed"
fi

# ---------------------------------------------------------------------------
say "S11: slot (the name resolver)"
# ---------------------------------------------------------------------------
# `slot` prints ONE line -- the slot directory -- for any path, and never
# answers existence. Lane launchers select their launch payload with it, so
# the encoding must never be reimplemented outside pinned.
mkdir -p "$SUB/s"
printf '{"measured": true}\n' > "$SUB/s/measured.json"
ANS='y
'
run_pinned approve --file "$SUB/s/measured.json"
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
ANS='y
'
run_pinned approve --file "$SUB/c/served.json" --store
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
ANS='y
'
run_pinned approve --file "$SUB/c/bare.txt"
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
ANS='y
'
run_pinned approve --file "$SUB/c/vanish.txt" --store
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
ANS='y
'
run_pinned approve --file "$SUB/c/served.json" --store
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
say ""
if [ "$FAIL" -eq 0 ]; then
  rm -rf "$FIX"
else
  say "fixtures kept for inspection: $FIX"
fi
say "passed=$PASS failed=$FAIL"
exit $(( FAIL > 0 ))
