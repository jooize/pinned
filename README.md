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
    pinned approve --file <path> [--baseline <copy>] [--file <path> ...] [--algo <name>]
                                      file-pin ceremony: freeze, display
                                      ROOT-SIDE, confirm, record the hash;
                                      several --file share one sudo
    pinned verify <path>              file-pin verdict for gates: 0 ok,
                                      10 no slot, 11 mismatch, 12 missing,
                                      13 tombstoned-but-present, 14 mode
                                      (--emit prints the verified bytes;
                                      --frozen <copy> checks held bytes)
    pinned tombstone <path>           retire a pinned file that is GONE
    pinned sign <repo> <tag>          signed release tag at the PINNED hash
    pinned signer add|list|remove [--repo <path>] (--file <pubkey> | --key '<line>')
                                      allowed-signers ceremony:
                                      fingerprint, confirm, write
    pinned status <repo|file>         record vs live state
    pinned review <file> [--algo <name>] [--length <bits>]
                                      trusted review of a non-repo file:
                                      one read, shown and hashed; no record
    pinned list [--under <dir>]       live pins: kind, digest, path
    pinned slot <repo>                print the repo's slot directory
    pinned migrate                    one-shot port of flat /etc/pinned

    pinned deploy [--dry-run] [--yes] [--flake <path>]
                                      sync every git+file input of the
                                      system flake to its approved rev
                                      (and declared tag ref), rebuild;
                                      shows the root commands first,
                                      never self-elevates

approve, setup, migrate, tombstone and signer add/remove self-elevate
via sudo (re-exec of the installed root-owned binary). sign and review
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
  `signers/allowed_signers`). Two state files at once is a malformed
  slot: every consumer refuses. `ls` reads a slot's whole state at a
  glance. `<user>/` is 0750 root:`_<user>-pinned` -- the group is
  consumed from the system config, never created, and its absence fails
  closed to root-only 0700. The wrapper subdirs are the mount menu: a
  lane mounts its own slot dirs (or `signers/` read-only), never
  `<user>/` itself, which would disclose every pinned path name.
  Consumers that want a friendly path use a root-owned symlink:
  `sudo ln -s "$(pinned slot <repo>)" /etc/nix-darwin/pinned-rev`.
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
  semantics; they read verify's exit code (0/10/11/12/13/14, stable
  API). Parsers use `--emit` (print the VERIFIED bytes, nothing on
  failure) or `--frozen <copy>` (verdict on caller-held bytes) so the
  bytes acted on are the bytes verified -- never verify-path-then-
  read-path. File modes are CHECKED as an invariant (owner is the tier
  user, no group/other write), not pinned as a value: content
  addressing catches rewrites; the owner can always chmod back.
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
  `signers/allowed_signers` first, the user tier's as fallback, so a key
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
