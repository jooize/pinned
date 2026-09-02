# pinned

Review-and-pin trust records behind a human gate. An agent can commit
anything to a repo you deploy from, or rewrite any file a gate reads;
nothing becomes trusted until a sudo ceremony says so. `pinned review`
shows the content root-side -- a repo's diff since the last approval
straight from the object store (scrubbed git environment: no user
config, no pager, no hooks), or a file's frozen bytes -- you approve,
and it writes the hash to a root-owned slot. Deploy tooling builds only
`git+file://...?rev=<pinned hash>`; file-gated consumers ask
`pinned verify`.

The design signature, and the test for every surface question: **the
root-owned record declares; the live world must conform; anything
undeclared refuses.** The slot declares the VCS (`rev.git`) and the
hash algorithm (`pin.sha256`) in its filenames -- never inferred from
attacker-writable content -- validation is exact per declaration, and
unknown declarations refuse outright.

## Commands

Full reference: `man pinned` — installed by the nix module; in-repo:
`man man/pinned.1`.

    pinned setup [--yes]              self-install + digest-pinned sudoers
    pinned review <repo>... [--tag <tag>] [--trust] [--step]
                             [--backward | --diverged]
                                      human gate: review diff -> pin
                                      (--tag: the tag's commit, not HEAD,
                                      and the declared release name;
                                      --trust: skip a first approval's
                                      full-tree review, loudly;
                                      --backward/--diverged: declare a pin
                                      move that is not forward over the
                                      commit graph -- the ceremony refuses
                                      unless reality matches the
                                      declaration, and says so loudly when
                                      it does;
                                      --step: reading aid for a large
                                      delta -- walk the commits since the
                                      pin oldest-first, one diff and one
                                      confirmation each, pin advancing at
                                      every yes, closing with a whole-run
                                      summary; ends at HEAD or at --tag's
                                      commit, declaring the name only if
                                      reached; one whole-delta diff stays
                                      the default)
    pinned review <repo> --signed-tag <tag> [--signed-tag <tag> ...] [--tag <tag>]
                                      signature gate: verify each signed tag,
                                      all naming one commit -> pin (--tag:
                                      an unsigned name that must agree)
    pinned review --file <path> [--baseline <copy>] [--ignore-json-key <key> ...]
                   [--file <path> ...] [--algo <name>] [--store]
                                      file-pin ceremony: freeze, display
                                      root-side, confirm, record the hash;
                                      several --file share one sudo
                                      (--ignore-json-key: keys whose later
                                      drift verify tolerates, each of which
                                      the ignorable policy must grant for
                                      that path; --store keeps a copy of
                                      the approved bytes in the slot)
    pinned verify <path>              file-pin verdict for gates: 0 ok,
                                      5 differs only in ignored keys,
                                      10 no slot, 11 mismatch,
                                      13 tombstoned-but-present,
                                      20 missing, 30 mode
                                      (--emit prints the verified bytes;
                                      --frozen <copy> checks held bytes;
                                      --baseline <copy> brings your own
                                      witness for the 5 comparison, for a
                                      slot that keeps none of its own)
    pinned cat <path>                 the approved bytes from root custody,
                                      on stdout -- the stored witness,
                                      re-hashed against the record first;
                                      nothing on stdout on any failure
                                      (0 served, 10 no record,
                                      13 tombstoned, 16 no stored copy,
                                      20 live file missing,
                                      30 slot invariant, 1 error)
    pinned tombstone <path>           retire a pinned file that is gone
    pinned rekey <old> <new>          re-key a record to the path its
                                      content has moved to: the rev or
                                      digest and every annotation travel
                                      verbatim, the content at <new>
                                      must already answer to the record
                                      (repo: a work-tree root whose
                                      object store holds the pinned
                                      commit; file: a re-hash to the
                                      recorded digest, or drift confined
                                      to the keys the slot already
                                      ignores), and <old> is tombstoned
    pinned declare <repo> --tag <name> | --remove
                                      name the release a pinned rev
                                      already is: the tag must already
                                      resolve to the pinned rev (checked,
                                      not taken -- the rev never moves),
                                      and deploy then syncs the input's
                                      ref= to it; --remove withdraws the
                                      declaration and the slot goes
                                      rev-only
    pinned sign <repo> <tag>          signed release tag at the pinned hash
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
    pinned show <file|repo> [--algo <name>] [--length <bits>]
                                      trusted re-display, no record: a
                                      file is one read, shown and hashed;
                                      a repo is the tree at its pin, from
                                      the object store
    pinned list [--under <dir>]       live pins: kind, digest, path
    pinned slot <path>                print the slot directory for any
                                      path -- repo, file, existing or
                                      not; a name, never an existence
                                      answer (exit 1 only if the path
                                      cannot be resolved)

    pinned add <repo|url> [--input <name>] [--signed-tag <tag>] [--flake <path>]
                                      checkout -> pin -> flake input, in
                                      three idempotent parts, each skipped
                                      with a note when already satisfied
                                      (all three satisfied: nothing to do):
                                      an existing directory is used in
                                      place, a url is cloned into
                                      /var/db/pinned-clones as you (never
                                      as root, scrubbed environment); the
                                      pin comes from review's own
                                      ceremony (--signed-tag rides through
                                      to it); the input block is shown in
                                      full and confirmed before the system
                                      flake is touched -- written with an
                                      all-zero rev and synced to the pin
                                      right after, so an interrupted add
                                      leaves an input that cannot be
                                      fetched rather than one that floats.
                                      Wiring the input into a
                                      configuration stays your edit:
                                      pinned never writes into the repos
                                      it gates

    pinned deploy [--dry-run] [--yes] [--flake <path>]
                                      sync every git+file input of the
                                      system flake to its approved rev
                                      (and declared tag ref), rebuild;
                                      shows the root commands first,
                                      never self-elevates. --flake
                                      defaults to /etc/nix-darwin/flake.nix
                                      (macOS) or /etc/nixos/flake.nix;
                                      unprivileged, any readable path is
                                      allowed, but run as root -- which
                                      only upgrade reaches -- the flake
                                      must be root-owned and not group- or
                                      other-writable, and so must every
                                      directory on the way to it

    pinned upgrade [--dry-run] [--yes] [--flake <path>]
                                      review every stale flake input
                                      (the same per-repo ceremonies),
                                      then deploy -- one authentication
                                      for the whole round; the plan runs
                                      unprivileged and decides whether
                                      there is an authentication at all:
                                      with nothing to approve upgrade
                                      exits there, pointing at `pinned
                                      deploy`, and with work to do a gate
                                      naming the round is the last line
                                      before sudo (--yes skips it),
                                      preceded by the exact sudo argv --
                                      --flake decides what the rebuild
                                      activates as root and --yes removes
                                      the last confirm, so neither reaches
                                      the password prompt undisclosed;
                                      upgrade self-elevates, so its --flake
                                      obeys deploy's root-side rule and a
                                      user-owned path is refused before any
                                      ceremony runs; the
                                      plan lists every input, one row
                                      each, and highlights only the ones
                                      a ceremony will cover -- the rest
                                      stay visible but quiet (at pin, no
                                      rev=, no slot, no checkout); a
                                      stale repo with a newer signed
                                      release an installed key verifies
                                      is offered the signature gate
                                      instead of a review; a
                                      tag-declared slot
                                      otherwise joins only when HEAD
                                      carries exactly one release tag
                                      (approved under that name), else it
                                      is listed for a manual review
                                      --tag; only forward checkouts join
                                      a ceremony, backward and diverged
                                      ones are listed as refused with the
                                      flag that would declare them

    pinned --version                  print the release version

review, add, setup, tombstone, rekey, declare, upgrade, signer add/remove
and ignorable add/remove self-elevate via sudo (re-exec of the
installed root-owned binary).
sign, show and cat
run as you: sign needs your SSH agent, show and cat write nothing. The
verb triple: `show` rehearses (no record), `review` records, `verify`
answers -- humans review, machines verify; the record happens only in
the review ceremony. The triple covers both kinds: `show <file>`
rehearses a hash gate, and `show <repo>` re-displays the tree a pin
already names,
through the same hardened git path the ceremony used. `cat` is
custody's reader, and reads nothing else.

Approval history: `log show --predicate 'eventMessage CONTAINS "pinned:"'`

## Design points

- Pins live in per-user slot directories: `/var/db/pinned/<user>/slots/`
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
- The tier has exactly two wrapper dirs, and they are the selection
  menu: `slots/` (what is pinned) and `policy/` (what may be trusted:
  `allowed_signers` and `ignorable.json`). A lane's launch payload
  carries its own slot dirs and `policy/`, never `<user>/` itself,
  which would disclose every pinned path name. Two rules produced this
  shape, and both rule out loose files directly under `<user>/`:
  - **Directories are the transfer unit, never files.** Every write
    here is an atomic rename over a staged temp file, so the name gets
    a new inode. Any consumer that binds a file (a root-owned symlink,
    a hypothetical file mount) would pin the pre-ceremony inode
    forever; naming the enclosing dir re-reads the name every time.
    Payload snapshots copy whole dirs for the same reason: a dir is a
    complete, self-consistent slot state.
  - **One dir per disclosure class.** Policy is small, boring and safe
    to expose; the slot list is itself information. Flat files would
    force a lane that needs the policy to carry the slot list with it.
  Consumers that want a friendly path use a root-owned symlink:
  `sudo ln -s "$(pinned slot <repo>)" /etc/nix-darwin/pinned-rev`.
  Slot names never leave pinned: `pinned slot <path>` resolves any path
  -- repo or file, existing or not -- to its slot directory, so a lane
  launcher selects its launch payload with it instead of reimplementing
  the encoding. It resolves a name and nothing more: it does not say
  whether the path is pinned (that is `verify`) or whether the directory
  exists (the caller's own `-d`).
- **Lanes get copies, not the ledger.** A lane receives a launch-time
  snapshot of just the slot dirs it needs, installed at the verbatim host
  paths by the lane's own root -- so the records are genuinely root-owned
  where they are read, and verification is the same strict check
  everywhere. `pinned` has no lane-conditional branch.
- First approval of a repo shows the full tree (diff from the empty
  tree) unless `--trust` is passed, loudly.
- **The ancestry lattice.** A ceremony that moves a pin first establishes
  which way it is moving, over the commit graph -- never by parsing a
  version string, because tag and branch names are repo content and
  version sort is only a convention. Four classes: `equal` (a no-op),
  `forward` (the candidate descends from the pin), `backward` (the
  candidate is an ancestor -- the commits between are being
  un-approved), `diverged` (neither -- the pinned line of history is
  being abandoned). Forward proceeds; the other two refuse unless the
  human declares them (`--backward`, `--diverged`), and a declaration
  reality contradicts refuses too, naming the class that actually holds
  -- declared, never inferred. A declared move opens with a full-caps
  alarm and shows its commits in the direction that makes them
  readable: the reversed range for backward, and the merge base plus
  both sides for diverged (an empty `pin..candidate` listing would say
  nothing about what is being withdrawn, which is the one thing a
  review may never do). The floor holds for signature evidence too: a
  signature says who vouched, never which way the pin is moving, so a
  replayed signed release of an older version is exactly what it
  catches. It governs ceremonies only -- `verify`, `status` and
  `deploy` answer about a pin already recorded and are untouched.
- The file-pin ceremony (`review --file`) takes no hash argument, ever.
  A hash handoff would let a caller in a poisoned environment feed root
  an opaque digest to record sight-unseen; instead the file is frozen
  and displayed exactly once, root-side, after sudo's environment reset,
  and the recorded hash is taken from the displayed buffer -- record ==
  seen, by construction. A caller's own display (diffs, structural
  views) is pre-sudo orientation, never what the record binds to.
  `--baseline <copy>` shows a diff instead of the full file, but only
  when the copy re-hashes to the previously recorded digest.
- `verify` is the one state table. Consumers never re-derive slot
  semantics; they read verify's exit code (0/5/10/11/13/20/30, stable
  API). The decade is the action class and the taxonomy is shared with
  `cat` (which adds **16**, "no stored witness"); 12/14/15 are retired
  numbers that are never reused. The numbering rule, settled: renumber
  wholesale when coherence demands it (as the sweep into decade classes
  did), never backfill a retired slot piecemeal -- a retired number is
  one some deployed consumer still remembers, and giving it a new
  meaning makes a running gate misread a verdict it thinks it
  understands, silently, until that consumer is redeployed.
  Parsers use `--emit` (print the verified bytes, nothing on
  failure) or `--frozen <copy>` (verdict on caller-held bytes) so the
  bytes acted on are the bytes verified -- never verify-path-then-
  read-path. File modes are checked as an invariant (owner is the tier
  user, no group/other write), not pinned as a value: content
  addressing catches rewrites; the owner can always chmod back.
- **Ignored keys:** a settings file whose `model` and `effortLevel` churn
  hourly should not summon a ceremony hourly, and those keys carry no
  hardening. A slot may therefore declare `ignored.json` -- a JSON array of
  jq key paths, e.g. `[["model"],["statusLine","command"]]` -- written only
  by the ceremony (`review --file <path> --ignore-json-key model
  --ignore-json-key effortLevel`). Semantics, in
  one sentence: **the pin stays byte-exact and ignoring is a verify-side
  tolerance.** `pin.<algo>` is still the hash of the approved bytes,
  `shasum -a 256 -c pin.sha256` still cross-checks it with stock tools, and
  nothing about what gets hashed changes. What changes is the answer to a
  mismatch: verify may compare the two documents with the declared keys
  projected out, and, if everything else is identical, answer **5**
  ("matches modulo declared ignored keys") instead of 11, naming each key
  that actually moved on stdout as `ignored-drift: <key>`. Consumers treat
  5 as permitted and unknown codes as refusal, exactly as before.
  - The format is declared by the suffix, like `rev.<vcs>` and
    `pin.<algo>`: `ignored.json` is the shipped grammar, and an
    `ignored.toml` / `ignored.yaml` / anything else refuses rather than
    being guessed at. That refusal is also the extension point -- adding a
    format means adding a reader and a flag, never inferring one. The
    content must be an array of nonempty arrays of strings; anything else
    (including an empty array, which would tolerate nothing) refuses.
  - The record is real JSON because the `.json` suffix has to be truthful,
    because that array is exactly what jq's `delpaths` takes (so the
    comparison consumes the record with no translation step), and because
    a JSON object key may contain any character at all -- dots, spaces,
    parentheses (`"Bash(git status:*)"` is a real settings key). A dotted
    line cannot spell those. Generality lives in the storage, convenience
    in the human surface: the CLI still takes `--ignore-json-key model` (or
    `a.b.c`), displays join paths back with dots, and dot-splitting happens
    only at that surface.
  - CLI key grammar: dotted `[A-Za-z0-9_.-]`, no leading/trailing/doubled
    dot, keys only. No array subscripts: an index is a position, not a
    name, and a tolerated position silently moves when something is
    inserted before it.
  - Comparing needs the last-approved bytes -- a witness (see "The record
    and its witnesses" below). Either the slot keeps one of its own
    (`review --file <path> --store`) or the caller brings one
    (`verify --baseline <copy> <path>`); with neither, verify stays at the
    byte-exact 11. A caller-brought copy must re-hash to the record before
    it is used -- the same self-verifying trick the ceremony's baseline
    diff uses, so a forged baseline can only make verify stricter.
  - If `approved` exists it must re-hash to the record beside it. A
    violation is a malformed slot (hard error, exit 1) rather than a
    degraded comparison -- what makes this harder than a declined witness
    is where the bytes are: root custody, which nothing unprivileged can
    have written, so root-owned bytes that are not the approved bytes are
    incoherent state, not weak evidence. Re-approve to reset it.
  - Parser differentials are the reason this path is so suspicious of its
    input. A structural comparison is only as honest as the agreement
    between the parser doing the comparing and the parser that will
    actually read the file. So the tolerance path refuses -- loudly, back
    to the byte-exact 11 -- on: duplicate object keys anywhere on either
    side (jq keeps the last, other parsers differ, and guessing which one
    a consumer keeps is exactly the uncertainty this tool exists to
    avoid); more than one top-level JSON document (jq reads a concatenated
    stream, everything else reads one value); NUL bytes (jq tolerates a
    trailing one, other parsers do not); an unparseable side; a missing
    baseline; a missing jq; and of course any difference outside the
    declared keys. Duplicate detection is empirical, not assumed:
    `jq --stream` emits one event per value occurrence while re-serializing
    through jq collapses duplicates to the last, so a differing event count
    proves a duplicate anywhere at any depth -- including duplicates whose
    values are objects, where the leaf paths differ and a path-multiset
    comparison would miss them.
  - The ceremony states the declaration prominently before the y/N, and an
    review without `--ignore-json-key` clears the declaration -- with a
    loud note whenever that narrows or widens what was there. The tag rule
    covers every extra a slot can hold: each is re-stated by every
    ceremony, so a review without `--store` drops a stored copy too, and
    identical bytes are a no-op only when the declaration and the custody
    state are identical as well.
  - A non-JSON file simply fails the parse step and always gets the
    byte-exact verdict; pinned never restricts which kinds of path may
    carry a declaration, only which keys (below).
- **The ignorable ladder.** What a slot may declare is itself gated, because
  "which keys may drift" is exactly the decision an attacker would like to
  make for you. Two root-owned policy tiers sit above the declaration, and
  every rung is checked at review and at verify:

      machine policy  >=  user policy     >=  slot declaration  >=  drift
      /etc/pinned/        <user>/policy/      slots/<enc>/          tolerated
      ignorable.json      ignorable.json      ignored.json          by verify

  - Both tiers are arrays of entries:
    `[{"path":["model"],"under":"/Users/x/.config"},{"path":["effortLevel"]}]`.
    `"under"` is optional and means everywhere when omitted; present, it is
    an absolute prefix matched at a component boundary, so `/a/b` covers
    `/a/b` and `/a/b/c` and never `/a/bb` -- the same rule `list --under`
    uses. No other object keys are accepted: one this version does not
    understand could be a narrowing constraint written by a newer one, and
    ignoring it would silently widen the grant.
  - The machine tier is optional (absent = no machine constraint) and is
    the file a configuration manager declares (nix: `environment.etc`).
    The user tier is the operative allow-list, managed by the `ignorable`
    ceremony. Absent or empty grants nothing, and an unreadable tier of
    either kind grants nothing either -- fail closed, in the direction that
    costs a ceremony rather than a tolerance.
  - Effective = the intersection: a user entry counts only if the machine
    tier has the same path with a scope covering it (a user entry with no
    scope is covered only by a machine entry with no scope). `pinned
    ignorable list` prints all three -- machine, user, effective -- with
    each entry's scope, so "why was this key dropped" is answerable from
    one unprivileged command.
  - `review --file --ignore-json-key <key>` refuses a key the effective
    policy does not grant for that path, loudly, and names the exact
    remediation (`sudo pinned ignorable add <key> --under <dir>`). The
    semantics are uniform: pinned cannot tell a human's argv from a calling
    tool's, so "a human typed it" is never a reason to allow it. The
    ceremony display then states the declared keys' grant provenance on one
    line (`granted by user policy, under /Users/x/.config: model`), so the
    ladder is audited on screen while the y/N is asked.
  - `verify` re-checks at use time: every key recorded in `ignored.json` must
    still be within the effective policy for that path, or the tolerance is
    refused and the answer is a plain 11 (with a note naming the key that
    lost its grant). Narrowing the policy therefore bites at the very next
    verify -- no re-ceremony, no stale grant surviving in a slot nobody
    revisits.
- Tombstones are sentinel slot content, never slot deletion: a pinned
  file that vanished refuses until restored or ceremonially tombstoned,
  and a tombstoned path that reappears refuses until re-approved --
  retired content resurrected must not read as merely new.
- A path is a record's identity, and `rekey` is how an identity changes
  hands without trust changing with it. The record travels verbatim and
  the machine -- not the human -- establishes the one new claim it makes:
  the content already at the new path must be exactly what the record
  names, or the ceremony refuses. So the only thing the human confirms is
  the thing the ceremony displays, and nothing becomes trusted that was
  not trusted a moment earlier. The old slot is tombstoned (not deleted)
  by the same move, because something reappearing at a formerly trusted
  path is exactly what has to fail closed.
- Signing exports the pin. `pinned sign` creates a perfectly normal
  signed release tag, but the hash it signs comes from the root-owned
  pin file: you read once at review; nothing is re-read at sign time,
  so a compromised environment has nothing to MITM (SSH-agent signing
  is blind -- the binding to content is this code path). `review --signed-tag`
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
  (`review <repo> --signed-tag v1.2.3-alice --signed-tag v1.2.3-bob`) -- every
  named tag must verify and name the same commit or nothing is pinned;
  k-of-n is the consumer demanding whichever k tags they trust.
- `upgrade` offers that gate. A stale repo whose tags include a newer
  signed release this machine's allowed signers verify is routed to
  `review --signed-tag` instead of a plain review -- the plan says
  `(signed release <t> -- signature-gated)`, and the ceremony's own
  `[y/N]` is the offer's acceptance (declining skips that repo, like any
  batch decline). It outranks both the release-at-HEAD rule and a plain
  review, for rev-only and tag-declared slots alike. There is still no
  latest-tag search: candidates must pass the declared-name grammar,
  strictly descend from the pin, and be an ancestor of the checkout's
  HEAD; each is then verified, and only the verified subset is ordered --
  by ancestry over the commit graph, never by name. The offer is that
  subset's unique ancestry maximum, and every verified tag naming that
  same commit rides along as the k-of-n agreement above. Selection is
  safe here precisely because nobody without the signer key can enter a
  candidate: an attacker-writable name never chooses what a ceremony
  covers. Verified tags on lines that do not contain one another have no
  maximum and are listed for a manual `review --signed-tag`.
- The pin-stating paths never execute what they approve; `deploy` is
  the one acting subcommand -- the bundled consumer for a nix system
  (a machine has exactly one configuration mechanism; any other
  consumer is the same primitive: read the pin, act on exactly that
  rev) -- and it acts only by composing and showing the commands that
  run as root, then running them under ordinary sudo -- it never
  self-elevates. It scans the system flake for `git+file://` inputs,
  syncs each stale `rev=` to its approved hash, and rebuilds -- the
  rebuild runs even when every rev is already in sync, because the
  flake matching the pins says nothing about what the system runs. A
  slot that declares a release tag also gets its `ref=` synced to
  `refs/tags/<tag>` -- after cross-checking that the live tag still
  names the approved rev; a moved or deleted tag is a clean fail-closed
  refusal, never a nix fetch error. `pinned declare` is how an
  already-pinned slot gains (or gives up) that name -- a review that
  moves the pin writes it too, and a plain review clears it. Inputs without a pin slot are
  surfaced loudly (they deploy as hand-edited); non-local inputs are
  not pinned's to speak for. One binary for gate and consumer is
  deliberate: one file to hand-read at bootstrap, and the sudoers
  digest attests the deployer too. Run the installed root-owned copy --
  deploy composes the exact commands that run as root, so a
  user-writable copy is a user-writable root command line.
- **`add` composes; it decides nothing.** One verb carries a repo from
  "it exists somewhere" to "pinned and wired in as a flake input", in
  three idempotent parts -- checkout, pin, wired input -- each skipped
  with a note when it is already satisfied, so an interrupted run is
  resumed by rerunning it. The pin is `review`'s own ceremony, called
  as-is (`--signed-tag` rides through to it): a second review path
  would be a second thing to audit. The flake edit reuses deploy's
  in-place editor. What add adds is the seams between them, and each
  seam is a refusal: a name already spoken for by another path, a
  detached HEAD with no declared tag (an input needs a ref), a flake
  with no `inputs = {` anchor (the block is printed for by-hand
  placement instead), a clone destination whose `origin` is not the url
  asked for. The `follows` line is written only when the *approved*
  tree's `flake.nix` declares a nixpkgs input -- read from the object
  store at the pinned rev, never from the editable work tree.
- **The placeholder dance.** `add` writes its input block with a rev of
  forty zeros and only then syncs it to the approved hash. A crash
  between the two leaves an input that can never be fetched, so the
  next rebuild fails loudly -- where a floating `ref=` would have
  quietly built whatever the branch happened to point at. Fail closed
  is cheaper than fail correct. A rerun of `add` reports the unsynced
  input and points at `deploy`, whose one job is syncing revs; add
  never does that job behind its back.
- **A url is transport; the ceremony is trust.** `add <url>` clones into
  the shared tree `/var/db/pinned-clones/<name>` -- as the invoking
  user, never as root: root supervises the directory, git does the
  networking unprivileged, with no user config, no credential helper,
  and `GIT_ALLOW_PROTOCOL` cut down to file/git/http/https/ssh (which
  is what shuts out `ext::`, where a "url" is a command line). A
  redirected or hostile remote is bounded by the review that follows,
  because trust binds after the fetch. The destination is reused only
  when it already holds a repository of its own whose `origin` is the
  url asked for; anything else is refused, never adopted. Clones are
  group-owned (`_pinned-clones`, declared by the nix module) so several
  operators share one checkout; without the group the clone belongs to
  the invoker and says so -- content addressing gates trust either way,
  so availability wins here, unlike the record tree, where an absent
  group fails closed to root-only.
- **`add` never edits a consuming repo.** It wires the input in and
  stops. Wiring that input into a configuration -- a module import, an
  overlay, an anchor template's mirror -- stays a human edit, because a
  tool that wrote into the repositories it gates would be approving its
  own changes. The close of a successful add says so and points at
  `pinned deploy`.
- Rendered diffs are never trusted blindly, in three layers: every git
  call sets `attr.tree` to the empty tree (so no `.gitattributes` can
  select a driver or filter for any subcommand -- the only repo-wide
  switch git offers); the review helper additionally forces
  `--no-ext-diff --no-textconv`; and reaching for any rendering
  subcommand (`diff`, `show`, `log -p`, `format-patch`, ...) another way
  is refused inside the script.
  Repo-local `.git/config` can define an external diff driver or
  textconv filter, selected by a `.gitattributes` that need not even be
  committed; both are attacker-writable, both are shell commands, and
  scrubbing the environment does not stop them. Unhardened, a driver can
  render any diff as arbitrary text -- a textconv mapping both sides to
  one constant shows an empty diff for a commit that changed everything
  -- and it executes during rendering, which for a tool that elevates
  before diffing means as root.
- `pinned show <file>` extends the same idea past git, for content
  that is gated by hash rather than by rev (e.g. a hook wired into a
  hash-checked settings file). The security-relevant act is the read:
  one read into memory, those bytes displayed, those bytes hashed --
  never two reads with a swap in between. It prints the digest plus a
  ready-to-paste fail-closed wrapper, so the consumer hashes exactly the
  way `show` did. Runs unprivileged (it writes nothing); it lives in a
  root-owned binary because a user-writable display script could show
  innocent bytes and hash malicious ones -- and unlike a falsified
  display, which fails closed at the next hash check, a falsified
  ceremony fails open. The digest equals what `shasum -a <algo> <file>`
  reports, so the ceremony can be cross-checked with ordinary tools.
  Algorithms go by their standard names: sha256/sha384/sha512 work
  everywhere; `blake2b-256/-384/-512` need `b2sum` (GNU coreutils) and
  `blake3` needs `b3sum`, each installed system-wide. blake3 is an XOF, so
  its output size is a flag, not part of the name: `--length <bits>`
  (default 256). sha1/md5 and any digest under 256 bits are
  refused: this hash is the gate. There is deliberately no flag naming a
  hasher path -- whatever computes the digest decides whether the gate
  passes, so it must resolve inside the trusted PATH.
- `pinned show <repo>` closes the same gap on the repo side: after a
  pin exists, a file pin can be re-read through custody (`cat` serves
  the stored witness), but a repo's content could only be re-read
  through ambient git -- exactly the falsifiable display the hardening
  above exists to refuse. It re-displays the tree at the pinned rev
  through `sgit`, records nothing, and reads from the object store, so
  a dirty work tree changes not a byte of what is shown. Unprivileged
  is right here: content-addressing carries the trust (the rev names
  the bytes, and the pin it comes from is root-owned), and the
  root-owned binary is what keeps the display path itself unswappable.
- Trust prerequisite: the interactive flow assumes your terminal and
  shell honestly relay what you type and see. Shell configuration is
  user-writable state -- a compromised config can alias `pinned`, fake
  any output, and no in-band check (absolute paths, verifier helpers)
  can prove otherwise from inside the session. The backstop that
  survives a lying shell is out-of-band: the sudo authentication
  dialog names the exact command it will run as root -- read it there.
  Given a trusted shell config, invoking bare `pinned` is fine.

## The record and its witnesses

Two kinds of thing live in a file slot, and keeping them apart is the
whole model.

The **record** is what was approved: a digest (`pin.<algo>`) plus the
ceremony's declarations (`ignored.json`, `tag`). Root-owned, one shape
always, and the only trust anchor -- nothing else in this tool
authorizes anything.

A **witness** is any bytes that re-hash to the record's digest.
Witnesses are evidence, never authority: every reader authenticates a
witness against the record before using it, so where a witness was
stored, and whose hands carried it there, cannot affect a verdict. Two
arrive by different roads and are otherwise the same kind of thing --
the slot's own `approved` copy (root custody, written by
`review --file <path> --store`) and a caller-brought copy
(`verify --baseline <copy>`). A witness can only ever narrow a
comparison -- enable the ignored-key projection, feed the ceremony's
baseline diff -- and never stands in for the live file: a pinned file
that is missing is exit 20 no matter how many witnesses agree on what
it used to say.

Custody is therefore opt-in. A stored witness serves the tolerant
comparison, archives exactly what was approved, and feeds the display of
what changed -- but it also turns a slot that discloses one digest into
one that discloses the file's whole content. Disclosure is bounded (the
host tier is 0750 root:`_<user>-pinned`, and a consumer that mounts a
slot is given only the slot dirs it is measured against, whose files it
already reads through those same mounts), but bounded is not
nothing, so it stays a per-slot human decision at the ceremony. Being
per-slot, it is also per-slot reportable: `pinned list` annotates every
file row with the answer -- a stored copy, or the note that there is
none -- on an indented continuation line, so taking inventory never
means reaching into a slot directory to find out.

### The consumer ladder

`verify` answers about a path; the consumer then has to use the content,
and the gap between the two is where a swap would fit. Three rungs close
it, in descending order of what the consuming software can be told to
do:

1. **It can read a path you nominate** -> point it at root custody: the
   slot's `approved` file, reached through a root-owned symlink at the
   slot directory (`sudo ln -s "$(pinned slot <path>)" /etc/<tool>/pin`,
   then read `/etc/<tool>/pin/approved`) -- the dir, never the file, for
   the same reason every other consumer binds a dir: each ceremony
   renames a fresh inode into place. No gap at all: the bytes it reads
   are the bytes root holds, and it never sees the editing surface.
2. **It can run a command** -> `pinned cat <path>`. Same bytes, with the
   re-hash against the record done for it, and a stdout contract:
   approved bytes or an empty stream, never a fragment.
3. **It reads fixed paths by its own logic** -> only the launch window
   needs guarding, and that is the consumer's own problem, not pinned's:
   verify immediately before handing control over, and accept that a
   rewrite after launch is outside what a pin can speak for.

Rungs 1 and 2 need custody (`--store`); rung 3 does not. Consumers that
must parse content and cannot do either use `verify --emit` or
`verify --frozen`, which bind the verdict and the bytes to one read.

## Glossary

The names above in one place -- the same bytes seen from different
sides, which is exactly where they get confused.

- **record** -- the root-owned slot content: digest plus declarations
  (ignored keys, tag). Always the authority.
- **witness** -- any bytes that re-hash to the record, at the moment
  they do; evidence that narrows a comparison, never authority. Earned
  per use, not a stored status.
- **`approved` (the slot copy)** -- the root-custody copy written at the
  ceremony, named for its provenance. Becomes a witness each time it
  re-hashes clean.
- **`pinned-baselines`** -- the consumer-owned candidate store (diff
  baselines for orientation displays); entries can go stale, and each
  becomes a witness only when a verify re-hashes it clean.
- **custody** -- who holds bytes at rest (root slot copy vs consumer
  store): a disclosure and trust fact about location, distinct from the
  record's authority.

## Display conventions

A trust ceremony is mostly a display, so the display has rules. They are
recorded here because consumers print around pinned's output (the
hardening repo's claude shim shows an orientation preview immediately
before handing off), and two speakers sharing a screen must not read as
one.

- **Banners name the program and bracket authority.** The ceremony opens
  with `=== pinned: review (authoritative) ===`; a caller's own preview
  opens with its own name and says `(orientation preview)`. Everything
  between a banner and the next one belongs to that speaker. One speaker
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
  +12/-4 lines`) orient a reader; they can lie about where a change sits
  and never about what changed, because every changed line prints
  regardless and the digest comes from the bytes, not the view.

## Bootstrap without executing unverified code

Every trust tool has a first-install chicken-and-egg: the only copy
that exists lives in a user-writable checkout. You never have to
execute that copy privileged, though. Copy it with the OS's own
tooling (which moves bytes but runs none of them), then read the copy
user-space can no longer touch, then run only what you read:

    sudo /usr/bin/install -d -o root -g wheel -m 755 /usr/local/sbin
    sudo /usr/bin/install -o root -g wheel -m 444 ./pinned /usr/local/sbin/pinned-unverified
    less /usr/local/sbin/pinned-unverified   # THE read that anchors trust
    sudo mv /usr/local/sbin/pinned-unverified /usr/local/sbin/pinned
    sudo chmod 755 /usr/local/sbin/pinned
    sudo /usr/local/sbin/pinned setup        # or: review <repo> --trust

The copy is verbatim, and one of the things you read on the first line
is why: the shebang names `/bin/bash` absolutely rather than going
through `env`. pinned self-elevates by re-exec'ing itself under sudo,
sudo passes the caller's PATH straight through to the root process, and
`env` would resolve that root interpreter from the caller's PATH -- so a
user-writable prefix ahead of the system dirs (`/opt/homebrew/bin` on an
ARM Mac) would supply the bash that runs as root, and the sudoers digest
could not object: it pins the script's bytes, not its interpreter.
`/bin/bash` is root-owned on stock macOS (SIP-sealed) and stock Linux,
so naming it leaves nothing to resolve. `setup` re-checks this on the
file it is about to digest-pin and refuses if the first line ever names
`env`, a relative path, or an interpreter that is not root-owned.

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

On a machine with no `/bin/bash` (NixOS is the one that matters here) a
checkout cannot exec itself; run it as `bash ./pinned <verb>`, and as
`sudo bash ./pinned setup`. Nothing is lost: the interpreter is
still named explicitly by the caller rather than resolved from a
user-writable PATH, and the declarative install below is the intended
route there anyway, since the module rewrites the first line to the
store bash at build time.

## Declarative install (nix-darwin / NixOS)

The manual route above is the first-class citizen: it works on any
machine with sudo and needs nothing but this file. If a
configuration-management tool builds your system, pinned can instead
be installed by that tool from an approved rev -- `setup` is then
never needed, because the deploy does setup's three jobs (binary,
sudoers digest, pin root) declaratively. This repo ships a Nix flake
for that:

1. Approve the config repo using the bootstrap above -- review
   creates the /var/db/pinned tree itself, so setup never runs:

       sudo /usr/local/sbin/pinned review <repo> --trust

2. Import the flake module and declare who may run it:

       inputs.pinned.url = "git+file:///path/to/pinned";   # rev-locked in flake.lock
       # in the system config:
       imports = [ inputs.pinned.darwinModules.default ];  # or nixosModules.default
       security.pinned = { enable = true; users = [ "USER" ]; };

   The module installs the script into the system profile and writes
   /etc/sudoers.d/pinned with an eval-time sha256 of the exact bytes
   it installs -- digest and binary derive from one source in one
   build, so they can never disagree. It rewrites the shebang to the
   store bash at build time, which is the same interpreter pinning the
   manual route does by hand, done by the packaging that knows its own
   root-owned prefix. It also declares the two groups
   the script consumes but never creates: `_<user>-pinned`, which makes
   that user's record tier readable, and `_pinned-clones`, the
   operators of the shared clone tree `pinned add <url>` fetches into.
   Neither directory is created here -- the script provisions both
   root-side, so a manual install lands on the same paths.
   nix/module.nix is short: read it.

3. Deploy (gated, builds the approved rev). The store-installed binary
   takes over; the bootstrap copy at /usr/local/sbin/pinned can be
   removed (`sudo rm`) -- the module's sudoers entry names only the
   system-profile path.

Full design: ../claude-code-hardening/design/PLAN-pinned.md
Family: ../locked (setup/verify patterns reused), ../sudowhat.
