# pinned

Review-and-pin a git rev. An agent can commit anything to a repo you
deploy from; nothing becomes system state until a human gate says so.
`sudo pinned approve` shows the diff since the last approval straight
from the object store (scrubbed git environment -- no user config, no
pager, no hooks), you approve, and it writes the hash to a root-owned
pin file. Deploy tooling builds only `git+file://...?rev=<pinned hash>`.

## Commands

    pinned setup [--yes]              self-install + digest-pinned sudoers
    pinned approve <repo> [--trust-current]
                                      human gate: review diff -> pin
    pinned approve <repo> --tag <tag>   signature gate: verify signed tag -> pin
    pinned sign <repo> <tag>          signed release tag at the PINNED hash
    pinned status <repo>
    pinned list                       all pins: hash and repo path
    pinned slot <repo>                print the repo's pin-file path

approve and setup self-elevate via sudo (re-exec of the installed
root-owned binary). sign runs as you: it needs your SSH agent.

Approval history: `log show --predicate 'eventMessage CONTAINS "pinned:"'`

## Design points

- Pins live in /etc/pinned/<encoded-repo-path>, root:wheel 644, written
  atomically. Consumers that want a friendly path use a root-owned
  symlink: `sudo ln -s "$(pinned slot <repo>)" /etc/nix-darwin/pinned-rev`.
- First approval of a repo shows the full tree (diff from the empty
  tree) unless `--trust-current` is passed, loudly.
- Signing exports the pin. `pinned sign` creates a perfectly normal
  signed release tag, but the hash it signs comes from the root-owned
  pin file: you read once at approve; nothing is re-read at sign time,
  so a compromised environment has nothing to MITM (SSH-agent signing
  is blind -- the binding to content is this code path). `approve --tag`
  verifies such a tag against root-owned allowed signers -- per-repo
  `<pin file>.signers` first, global /etc/pinned/allowed_signers as
  fallback, so a key trusted for one repo doesn't implicitly vouch for
  every repo (git's native format); any repo with signed releases works with no
  pinned-specific conventions. Second-machine bootstrap: clone
  anywhere, install the signer key once (obtained out of band), approve
  the tag.
- One tag holds one signature. Sign an existing tag only if it already
  points at the pinned rev (promoting an unsigned release); moving a
  tag is refused. Co-signers use distinct tag names by convention
  (v1.2.3-alice, v1.2.3-bob) -- consumers approve whichever name they
  trust; allowed_signers is any-of.
- Deploy consumers are separate scripts: pinned states trust, never
  acts on it.
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
    sudo /usr/local/sbin/pinned setup        # or: approve <repo> --trust-current

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

Machines whose system config pinned will gate can skip `setup`
entirely and install pinned from an approved rev instead:

1. Approve the config repo using the bootstrap above -- approve
   creates /etc/pinned itself, so setup never runs:

       sudo /usr/local/sbin/pinned approve <repo> --trust-current

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
