# pinned

Review-and-pin trust records behind a human gate. An agent can commit
anything to a repo you deploy from, or rewrite any file a gate reads;
nothing becomes trusted until a sudo ceremony says so. `pinned approve`
shows the content root-side -- a repo's diff since the last approval
straight from the object store (scrubbed git environment: no user
config, no pager, no hooks), or a file's frozen bytes -- you approve,
and it writes the hash to a root-owned slot. Deploy tooling builds only
`git+file://...?rev=<pinned hash>`; file-gated consumers ask
`pinned verify`.

The design signature, and the test for every surface question: **the
root-owned record DECLARES; the live world must CONFORM; anything
undeclared REFUSES.** The slot declares the VCS (`rev.git`) and the
hash algorithm (`pin.sha256`) in its filenames -- never inferred from
attacker-writable content -- validation is exact per declaration, and
unknown declarations refuse outright.

## Commands

    pinned setup [--yes]              self-install + digest-pinned sudoers
    pinned approve <repo> [--tag <tag>] [--trust]
                                      human gate: review diff -> pin
                                      (--tag: the tag's commit, not HEAD,
                                      and the declared release name;
                                      --trust: skip a first approval's
                                      full-tree review, loudly)
    pinned approve <repo> --signed-tag <tag> [--signed-tag <tag> ...] [--tag <tag>]
                                      signature gate: verify signed tag(s),
                                      all naming one commit -> pin (--tag:
                                      an unsigned name that must agree)
    pinned approve --file <path> [--baseline <copy>] [--ignore-json-key <key> ...]
                   [--file <path> ...] [--algo <name>] [--store]
                                      file-pin ceremony: freeze, display
                                      ROOT-SIDE, confirm, record the hash;
                                      several --file share one sudo
                                      (--ignore-json-key: keys whose later
                                      drift verify tolerates, each of which
                                      the ignorable policy must grant for
                                      that path; --store also keeps the
                                      approved bytes in the slot)
    pinned verify <path>              file-pin verdict for gates: 0 ok,
                                      5 differs only in ignored keys,
                                      10 no slot, 11 mismatch,
                                      13 tombstoned-but-present,
                                      20 missing, 30 mode
                                      (--emit prints the verified bytes;
                                      --frozen <copy> checks held bytes;
                                      --baseline <copy> offers the last
                                      approved bytes for the 5 comparison)
    pinned tombstone <path>           retire a pinned file that is GONE
    pinned sign <repo> <tag>          signed release tag at the PINNED hash
    pinned signer add|list|remove [--repo <path>] (--file <pubkey> | --key '<line>')
                                      allowed-signers ceremony:
                                      fingerprint, confirm, write
    pinned ignorable add|remove <key> [--under <dir>]
                                      grant/withdraw a key that a ceremony
                                      may declare ignored; --under scopes
                                      the grant to a directory's subtree,
                                      omitted means everywhere
    pinned ignorable list             machine tier, user tier, and the
                                      effective intersection, with scopes
    pinned status <repo|file>         record vs live state
    pinned review <file> [--algo <name>] [--length <bits>]
                                      trusted review of a non-repo file:
                                      one read, shown and hashed; no record
    pinned list [--under <dir>]       live pins: kind, digest, path
    pinned slot <path>                print the slot directory for any
                                      path -- repo, file, existing or
                                      not; a name, never an existence
                                      answer (exit 1 only if the path
                                      cannot be resolved)

    pinned deploy [--dry-run] [--yes] [--flake <path>]
                                      sync every git+file input of the
                                      system flake to its approved rev
                                      (and declared tag ref), rebuild;
                                      shows the root commands first,
                                      never self-elevates

approve, setup, tombstone, signer add/remove and ignorable add/remove
self-elevate via sudo (re-exec of the installed root-owned binary).
sign and review
run as you: sign needs your SSH agent, review writes nothing. The verb
triple: `review` rehearses (no record), `approve` records, `verify`
answers -- humans review, machines verify, records happen only in
approve.

Approval history: `log show --predicate 'eventMessage CONTAINS "pinned:"'`

## Design points

- Pins live in per-user SLOT DIRECTORIES: `/var/db/pinned/<user>/slots/`
  `<encoded-path>/`, each holding exactly one of `rev.<vcs>` (repo pin,
  one full hash), `pin.<algo>` (file pin, one pure shasum-style check
  line carrying the live absolute path -- `shasum -a 256 -c pin.sha256`
  verifies with no pinned involved) or `tombstone` (one ISO line;
  existence is the semantics), plus optional annotations (`tag`,
  `ignored.<format>`, `approved`, `signers/allowed_signers`). Two state
  files at once is a malformed slot: every consumer refuses. `ls` reads a slot's whole state at a
  glance. `<user>/` is 0750 root:`_<user>-pinned` -- the group is
  consumed from the system config, never created, and its absence fails
  closed to root-only 0700.
- The tier has exactly TWO wrapper dirs, and they are the MOUNT MENU:
  `slots/` (what IS pinned) and `policy/` (what MAY be trusted:
  `allowed_signers` and `ignorable.json`). A lane mounts its own slot
  dirs and `policy/` read-only, never `<user>/` itself, which would
  disclose every pinned path name. Two rules produced this shape, and
  both rule out loose files directly under `<user>/`:
  - **Directories are mounted, never files.** Every write here is an
    atomic rename over a staged temp file, so the name gets a NEW inode
    -- and a bind-mounted (or virtiofs-shared) FILE pins the inode it
    was mounted from, so a guest would keep reading pre-ceremony bytes
    forever. Sharing the enclosing dir re-reads the name every time.
  - **One dir per disclosure class.** Policy is small, boring and safe
    to expose; the slot LIST is itself information. Flat files would
    force a lane that needs the policy to mount the slot list with it.
  Consumers that want a friendly path use a root-owned symlink:
  `sudo ln -s "$(pinned slot <repo>)" /etc/nix-darwin/pinned-rev`.
  SLOT NAMES NEVER LEAVE PINNED: `pinned slot <path>` resolves any path
  -- repo or file, existing or not -- to its slot directory, so a lane
  launcher builds its mount list with it instead of reimplementing the
  encoding. It resolves a NAME and nothing more: it does not say whether
  the path is pinned (that is `verify`) or whether the directory exists
  (the caller's own `-d`).
- IN A VM LANE, RECORDS CANNOT BE ROOT-OWNED. Apple Virtualization's
  virtiofs ignores ownership: a shared file presents in-guest as owned by
  whoever accesses it, and there is no ownership-honoring remount. So on
  a machine the kernel reports as a guest (`kern.hv_vmm_present` is 1),
  the READ paths -- and only they -- also accept a record presented as
  owned by the invoking user; the group/other-write refusal stays
  unconditional, and approving stays a host ceremony. The bytes are still
  the host's (the share is read-only), and faking that presentation
  in-guest needs guest root, which is already inside the boundary the
  human consented to by launching the lane. A host answers 0, so host
  verification is unchanged.
- First approval of a repo shows the full tree (diff from the empty
  tree) unless `--trust` is passed, loudly.
- The file-pin ceremony (`approve --file`) takes NO hash argument, ever.
  A hash handoff would let a caller in a poisoned environment feed root
  an opaque digest to record sight-unseen; instead the file is frozen
  and displayed exactly once, ROOT-SIDE, after sudo's environment reset,
  and the recorded hash is taken from the displayed buffer -- record ==
  seen, by construction. A caller's own display (diffs, structural
  views) is pre-sudo orientation, never what the record binds to.
  `--baseline <copy>` shows a diff instead of the full file, but only
  when the copy re-hashes to the previously recorded digest.
- `verify` is the one state table. Consumers never re-derive slot
  semantics; they read verify's exit code (0/5/10/11/13/20/30, stable
  API; the decade is the action class, and 12/14/15 are retired numbers
  that are never reused). Parsers use `--emit` (print the VERIFIED bytes, nothing on
  failure) or `--frozen <copy>` (verdict on caller-held bytes) so the
  bytes acted on are the bytes verified -- never verify-path-then-
  read-path. File modes are CHECKED as an invariant (owner is the tier
  user, no group/other write), not pinned as a value: content
  addressing catches rewrites; the owner can always chmod back.
- IGNORED KEYS: a settings file whose `model` and `effortLevel` churn
  hourly should not summon a ceremony hourly, and those keys carry no
  hardening. A slot may therefore declare `ignored.json` -- a JSON array of
  jq key paths, e.g. `[["model"],["statusLine","command"]]` -- written ONLY
  by the ceremony (`approve --file <path> --ignore-json-key model
  --ignore-json-key effortLevel`). Semantics, in
  one sentence: **the pin stays byte-exact and ignoring is a VERIFY-side
  tolerance.** `pin.<algo>` is still the hash of the approved bytes,
  `shasum -a 256 -c pin.sha256` still cross-checks it with stock tools, and
  nothing about what gets hashed changes. What changes is the answer to a
  MISMATCH: verify may compare the two documents with the declared keys
  projected out, and, if everything else is identical, answer **5**
  ("matches modulo declared ignored keys") instead of 11, naming each key
  that actually moved on stdout as `ignored-drift: <key>`. Consumers treat
  5 as permitted and unknown codes as refusal, exactly as before.
  - The FORMAT is declared by the suffix, like `rev.<vcs>` and
    `pin.<algo>`: `ignored.json` is the shipped grammar, and an
    `ignored.toml` / `ignored.yaml` / anything else REFUSES rather than
    being guessed at. That refusal is also the extension point -- adding a
    format means adding a reader and a flag, never inferring one. The
    content must be an array of nonempty arrays of strings; anything else
    (including an empty array, which would tolerate nothing) refuses.
  - The record is REAL JSON because the `.json` suffix has to be truthful,
    because that array is exactly what jq's `delpaths` takes (so the
    comparison consumes the record with no translation step), and because
    a JSON object key may contain any character at all -- dots, spaces,
    parentheses (`"Bash(git status:*)"` is a real settings key). A dotted
    line cannot spell those. GENERALITY LIVES IN THE STORAGE, CONVENIENCE
    IN THE HUMAN SURFACE: the CLI still takes `--ignore-json-key model` (or
    `a.b.c`), displays join paths back with dots, and dot-splitting happens
    only at that surface.
  - CLI key grammar: dotted `[A-Za-z0-9_.-]`, no leading/trailing/doubled
    dot, KEYS ONLY. No array subscripts: an index is a position, not a
    name, and a tolerated position silently moves when something is
    inserted before it.
  - Comparing needs the LAST-APPROVED bytes. `--store` keeps them in the
    slot as `approved`; otherwise the caller passes
    `verify --baseline <copy> <path>` and the copy must re-hash to the
    record before it is used (the same self-verifying trick the ceremony's
    baseline diff uses -- a forged baseline can only make verify
    STRICTER). The copy is OPT-IN because the lanes read-only mount slot
    directories into containers and VMs: a slot that today discloses one
    hash would then disclose the file's whole CONTENT there. That is a
    per-slot human decision at the ceremony, not a default.
  - If `approved` exists it MUST re-hash to the record beside it. A
    violation is a MALFORMED SLOT (hard error, exit 1) rather than a
    degraded comparison -- a slot either holds coherent state or it does
    not; re-approve to reset it.
  - PARSER DIFFERENTIALS are the reason this path is so suspicious of its
    input. A structural comparison is only as honest as the agreement
    between the parser doing the comparing and the parser that will
    actually read the file. So the tolerance path refuses -- loudly, back
    to the byte-exact 11 -- on: DUPLICATE object keys anywhere on either
    side (jq keeps the last, other parsers differ, and guessing which one
    a consumer keeps is exactly the uncertainty this tool exists to
    avoid); more than one top-level JSON document (jq reads a concatenated
    stream, everything else reads one value); NUL bytes (jq tolerates a
    trailing one, other parsers do not); an unparseable side; a missing
    baseline; a missing jq; and of course any difference outside the
    declared keys. Duplicate detection is empirical, not assumed:
    `jq --stream` emits one event per value OCCURRENCE while re-serializing
    through jq collapses duplicates to the last, so a differing event count
    proves a duplicate anywhere at any depth -- including duplicates whose
    values are objects, where the leaf paths differ and a path-multiset
    comparison would miss them.
  - The ceremony states the declaration prominently before the y/N, and an
    approve WITHOUT `--ignore-json-key` CLEARS both the declaration and the
    copy -- extras are re-declared every time, exactly like `tag` -- with a
    loud note whenever that narrows or widens what was there.
  - A non-JSON file simply fails the parse step and always gets the
    byte-exact verdict; pinned never restricts which KINDS of path may
    carry a declaration, only which keys (below).
- THE IGNORABLE LADDER. What a slot may declare is itself gated, because
  "which keys may drift" is exactly the decision an attacker would like to
  make for you. Two root-owned policy tiers sit above the declaration, and
  every rung is checked at approve AND at verify:

      machine policy  >=  user policy     >=  slot declaration  >=  drift
      /etc/pinned/        <user>/policy/      slots/<enc>/          tolerated
      ignorable.json      ignorable.json      ignored.json          by verify

  - Both tiers are arrays of entries:
    `[{"path":["model"],"under":"/Users/x/.config"},{"path":["effortLevel"]}]`.
    `"under"` is optional and means EVERYWHERE when omitted; present, it is
    an absolute prefix matched at a COMPONENT BOUNDARY, so `/a/b` covers
    `/a/b` and `/a/b/c` and never `/a/bb` -- the same rule `list --under`
    uses. No other object keys are accepted: one this version does not
    understand could be a narrowing constraint written by a newer one, and
    ignoring it would silently widen the grant.
  - The MACHINE tier is optional (absent = no machine constraint) and is
    the file a configuration manager declares (nix: `environment.etc`).
    The USER tier is the operative allow-list, managed by the `ignorable`
    ceremony. Absent or empty grants NOTHING, and an unreadable tier of
    either kind grants nothing either -- fail closed, in the direction that
    costs a ceremony rather than a tolerance.
  - EFFECTIVE = the intersection: a user entry counts only if the machine
    tier has the same path with a scope covering it (a user entry with no
    scope is covered only by a machine entry with no scope). `pinned
    ignorable list` prints all three -- machine, user, effective -- with
    each entry's scope, so "why was this key dropped" is answerable from
    one unprivileged command.
  - `approve --file --ignore-json-key <key>` REFUSES a key the effective
    policy does not grant for that path, loudly, and names the exact
    remediation (`sudo pinned ignorable add <key> --under <dir>`). The
    semantics are UNIFORM: pinned cannot tell a human's argv from a calling
    tool's, so "a human typed it" is never a reason to allow it. The
    ceremony display then states each declared key's grant PROVENANCE
    (`model -- user policy, under /Users/x/.config`), so the ladder is
    audited on screen while the y/N is asked.
  - VERIFY re-checks at use time: every key recorded in `ignored.json` must
    still be within the effective policy FOR THAT PATH, or the tolerance is
    refused and the answer is a plain 11 (with a note naming the key that
    lost its grant). Narrowing the policy therefore bites at the very next
    verify -- no re-ceremony, no stale grant surviving in a slot nobody
    revisits.
- Tombstones are sentinel slot CONTENT, never slot deletion: a pinned
  file that vanished refuses until restored or ceremonially tombstoned,
  and a tombstoned path that REAPPEARS refuses until re-approved --
  retired content resurrected must not read as merely new.
- Signing exports the pin. `pinned sign` creates a perfectly normal
  signed release tag, but the hash it signs comes from the root-owned
  pin file: you read once at approve; nothing is re-read at sign time,
  so a compromised environment has nothing to MITM (SSH-agent signing
  is blind -- the binding to content is this code path). `approve --signed-tag`
  verifies such a tag against root-owned allowed signers -- the slot's
  `signers/allowed_signers` first, the user tier's
  `policy/allowed_signers` as fallback, so a key
  trusted for one repo doesn't implicitly vouch for every repo (OpenSSH's
  SSHSIG allowed_signers format, git's native SSH signing end to end --
  stock `ssh-keygen -Y` verification, nothing pinned-specific); any repo
  with signed releases works with no pinned-specific conventions.
  Second-machine bootstrap: clone anywhere, install the signer key once
  with `pinned signer add` (obtained out of band), approve the tag.
- One tag holds one signature. Sign an existing tag only if it already
  points at the pinned rev (promoting an unsigned release); moving a
  tag is refused. Co-signers use distinct tag names by convention
  (v1.2.3-alice, v1.2.3-bob) -- consumers approve whichever name they
  trust; allowed_signers is any-of. Threshold multisig: repeat --signed-tag
  (`approve <repo> --signed-tag v1.2.3-alice --signed-tag v1.2.3-bob`) -- every
  named tag must verify and name the same commit or nothing is pinned;
  k-of-n is the consumer demanding whichever k tags they trust.
- The pin-stating paths never execute what they approve; `deploy` is
  the one acting subcommand -- the bundled consumer for a nix system
  (a machine has exactly one configuration mechanism; any other
  consumer is the same primitive: read the pin, act on exactly that
  rev) -- and it acts only by composing and SHOWING the commands that
  run as root, then running them under ordinary sudo -- it never
  self-elevates. It scans the system flake for `git+file://` inputs,
  syncs each stale `rev=` to its approved hash, and rebuilds -- the
  rebuild runs even when every rev is already in sync, because the
  flake matching the pins says nothing about what the SYSTEM runs. A
  slot that declares a release tag also gets its `ref=` synced to
  `refs/tags/<tag>` -- after cross-checking that the LIVE tag still
  names the approved rev; a moved or deleted tag is a clean fail-closed
  refusal, never a nix fetch error. Inputs without a pin slot are
  surfaced loudly (they deploy as hand-edited); non-local inputs are
  not pinned's to speak for. One binary for gate and consumer is
  deliberate: one file to hand-read at bootstrap, and the sudoers
  digest attests the deployer too. Run the installed root-owned copy --
  deploy composes the exact commands that run as root, so a
  user-writable copy is a user-writable root command line.
- Rendered diffs are never trusted blindly, in three layers: every git
  call sets `attr.tree` to the empty tree (so no `.gitattributes` can
  select a driver or filter for ANY subcommand -- the only repo-wide
  switch git offers); the review helper additionally forces
  `--no-ext-diff --no-textconv`; and reaching for any rendering
  subcommand (`diff`, `show`, `log -p`, `format-patch`, ...) another way
  is refused inside the script.
  Repo-local `.git/config` can define an external diff driver or
  textconv filter, selected by a `.gitattributes` that need not even be
  committed; both are attacker-writable, both are shell commands, and
  scrubbing the environment does not stop them. Unhardened, a driver can
  render any diff as arbitrary text -- a textconv mapping both sides to
  one constant shows an EMPTY diff for a commit that changed everything
  -- and it EXECUTES during rendering, which for a tool that elevates
  before diffing means as root.
- `pinned review <file>` extends the same idea past git, for content
  that is gated by hash rather than by rev (e.g. a hook wired into a
  hash-checked settings file). The security-relevant act is the READ:
  one read into memory, those bytes displayed, those bytes hashed --
  never two reads with a swap in between. It prints the digest plus a
  ready-to-paste fail-closed wrapper, so the consumer hashes exactly the
  way `review` did. Runs unprivileged (it writes nothing); it lives in a
  root-owned binary because a user-writable review script could show
  innocent bytes and hash malicious ones -- and unlike a falsified
  display, which fails closed at the next hash check, a falsified
  ceremony fails OPEN. The digest equals what `shasum -a <algo> <file>`
  reports, so the ceremony can be cross-checked with ordinary tools.
  Algorithms go by their standard names: sha256/sha384/sha512 work
  everywhere; `blake2b-256/-384/-512` need `b2sum` (GNU coreutils) and
  `blake3` needs `b3sum`, each installed system-wide. blake3 is an XOF, so
  its output size is a flag, not part of the name: `--length <bits>`
  (default 256). sha1/md5 and any digest under 256 bits are
  refused: this hash is the gate. There is deliberately no flag naming a
  hasher PATH -- whatever computes the digest decides whether the gate
  passes, so it must resolve inside the trusted PATH.
- Trust prerequisite: the interactive flow assumes your terminal and
  shell honestly relay what you type and see. Shell configuration is
  user-writable state -- a compromised config can alias `pinned`, fake
  any output, and no in-band check (absolute paths, verifier helpers)
  can prove otherwise from inside the session. The backstop that
  survives a lying shell is out-of-band: the sudo authentication
  dialog names the exact command it will run as root -- read it there.
  Given a trusted shell config, invoking bare `pinned` is fine.

## Display conventions

A trust ceremony is mostly a display, so the display has rules. They are
recorded here because consumers print around pinned's output (the
hardening repo's claude shim shows an orientation preview immediately
before handing off), and two speakers sharing a screen must not read as
one.

- **Banners name the program and bracket authority.** The ceremony opens
  with `=== pinned: approve (authoritative) ===`; a caller's own preview
  opens with its own name and says `(orientation preview)`. Everything
  between a banner and the next one belongs to that speaker. ONE speaker
  per banner region -- pinned never prints inside a caller's block, and a
  caller never annotates inside pinned's.
- **A caller's display is orientation; pinned's is authority.** The
  ceremony's hash comes from the buffer the ceremony itself displayed, so
  a caller's richer preview (structural diffs, changed-key summaries) is a
  reading aid that no record binds to.
- **Field lines are lowercase `label:` + value**, padded to one column
  (`file:`, `approved:`, `sha256:`, `ignored:`, `state:`). Stage-boundary
  statements are Sentence case sentences. Full caps only for a deliberate
  alarm (`!!! FIRST APPROVAL WITH --trust !!!`) -- never as generic
  emphasis.
- **Colour roles** are fixed: red = failure, green = success, yellow =
  attention, cyan = identifiers (paths, hashes, keys, tags), dim =
  secondary detail, bold = structure and authority. Colour is decoration
  only: with a non-tty stdout (or `NO_COLOR` for the two content
  highlighters) every display degrades to byte-identical plain text.
- **Glyphs**: `✓` recorded/verified, `✗` refused, `~` matched with a
  declared tolerance.
- **Paging** is `less -RF` through a fixed trusted path -- never `$PAGER`
  or user config, since the pager sits between reviewed bytes and eyes.
  `-F` means one-screen content prints inline and never takes over the
  alternate screen; longer content gets the alternate screen and real
  scrollback.
- **Structural views are derived; the raw byte diff is authoritative.**
  Section labels, changed-key summaries and shape lines (`3 hunks,
  +12/-4 lines`) orient a reader; they can lie about WHERE a change sits
  and never about WHAT changed, because every changed line prints
  regardless and the digest comes from the bytes, not the view.

## Bootstrap without executing unverified code

Every trust tool has a first-install chicken-and-egg: the only copy
that exists lives in a user-writable checkout. You never have to
EXECUTE that copy privileged, though. Copy it with the OS's own
tooling (which moves bytes but runs none of them), then read the copy
user-space can no longer touch, then run only what you read:

    sudo /usr/bin/install -d -o root -g wheel -m 755 /usr/local/sbin
    sudo /usr/bin/install -o root -g wheel -m 444 ./pinned /usr/local/sbin/pinned-unverified
    less /usr/local/sbin/pinned-unverified   # THE read that anchors trust
    sudo mv /usr/local/sbin/pinned-unverified /usr/local/sbin/pinned
    sudo chmod 755 /usr/local/sbin/pinned
    sudo /usr/local/sbin/pinned setup        # or: approve <repo> --trust

The staging keeps two invariants visible in the filesystem: the final
name only ever holds bytes a human has read, and the execute bit only
ever exists under the final name -- staged bytes cannot be exec'd at
all (mode 444; the kernel refuses). Promotion is `mv` + `chmod`, not
pinned code: trusted tooling, inode-preserving, so the bytes you read
are exactly the bytes promoted. mv before chmod -- a non-executable
verified file fails closed; an executable -unverified would not.
Never execute anything named -unverified (the x-bit stops exec, not
`bash pinned-unverified` -- the name rule still carries).

Reading the checkout beforehand is still sensible, but it can never be
conclusive -- anything running as you can swap the file between your
read and any use of it. The root-owned copy cannot change, so the
read after install is the one that counts. Privileged execution then
touches only system binaries (sudo, install, less, mv) and bytes you
have read.

The direct route (running the checkout as root via setup or the
pre-install fallback) still works and warns loudly; prefer this one.

## Declarative install (nix-darwin / NixOS)

The manual route above is the first-class citizen: it works on any
machine with sudo and needs nothing but this file. If a
configuration-management tool builds your system, pinned can instead
be installed BY that tool FROM an approved rev -- `setup` is then
never needed, because the deploy does setup's three jobs (binary,
sudoers digest, pin root) declaratively. This repo ships a Nix flake
for that:

1. Approve the config repo using the bootstrap above -- approve
   creates the /var/db/pinned tree itself, so setup never runs:

       sudo /usr/local/sbin/pinned approve <repo> --trust

2. Import the flake module and declare who may run it:

       inputs.pinned.url = "git+file:///path/to/pinned";   # rev-locked in flake.lock
       # in the system config:
       imports = [ inputs.pinned.darwinModules.default ];  # or nixosModules.default
       security.pinned = { enable = true; users = [ "USER" ]; };

   The module installs the script into the system profile and writes
   /etc/sudoers.d/pinned with an eval-time sha256 of the exact bytes
   it installs -- digest and binary derive from one source in one
   build, so they can never disagree. nix/module.nix is short: read it.

3. Deploy (gated, builds the approved rev). The store-installed binary
   takes over; the bootstrap copy at /usr/local/sbin/pinned can be
   removed (`sudo rm`) -- the module's sudoers entry names only the
   system-profile path.

Full design: ../claude-code-hardening/design/PLAN-pinned.md
Family: ../locked (setup/verify patterns reused), ../sudowhat.
