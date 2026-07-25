# pinned

Review-and-pin a git rev. An agent can commit anything to a repo you
deploy from; nothing becomes system state until a human gate says so.
`sudo pinned approve` shows the diff since the last approval straight
from the object store (scrubbed git environment -- no user config, no
pager, no hooks), you approve, and it writes the SHA to a root-owned
pin file. Deploy tooling builds only `git+file://...?rev=<pinned sha>`.

## Commands

    pinned setup [--yes]              self-install + digest-pinned sudoers
    pinned approve <repo> [--trust-current]
                                      human gate: review diff -> pin
    pinned approve <repo> --tag <tag>   signature gate: verify signed tag -> pin
    pinned sign <repo> <tag>          signed release tag at the PINNED sha
    pinned status <repo>
    pinned list                       all pins: sha and repo path
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
  signed release tag, but the sha it signs comes from the root-owned
  pin file: you read once at approve; nothing is re-read at sign time,
  so a compromised environment has nothing to MITM (SSH-agent signing
  is blind -- the binding to content is this code path). `approve --tag`
  verifies such a tag against root-owned /etc/pinned/allowed_signers
  (git's native format); any repo with signed releases works with no
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

## Declarative install (nix-darwin / NixOS)

Machines whose system config pinned will gate can skip `setup`
entirely and install pinned from an approved rev instead:

1. Hand-read the script, then approve the config repo with the
   checkout copy: `pinned approve <repo> --trust-current`.
   Self-elevation falls back to the checkout pre-install -- loudly,
   with a confirm, since that copy is user-writable.
2. Declare in the config: the script installed root-owned from the
   store, plus the sudoers entry with a build-time digest so it tracks
   every update automatically:

       environment.etc."sudoers.d/pinned".text =
         "USER ALL=(root) sha256:${builtins.hashFile "sha256" ./pinned} <installed-path>\n";

3. Deploy (gated, builds the approved rev). The store-installed binary
   takes over; the fallback never fires again.

Full design: ../claude-code-hardening/design/PLAN-pinned.md
Family: ../locked (setup/verify patterns reused), ../sudowhat.
