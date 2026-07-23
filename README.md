# pinned

Review-and-pin a git rev. An agent can commit anything to a repo you
deploy from; nothing becomes system state until a human gate says so.
`sudo pinned bless` shows the diff since the last blessing straight
from the object store (scrubbed git environment -- no user config, no
pager, no hooks), you approve, and it writes the SHA to a root-owned
pin file. Deploy tooling builds only `git+file://...?rev=<pinned sha>`.

## Commands

    sudo pinned setup [--yes]              self-install + digest-pinned sudoers
    sudo pinned bless <repo> [--trust-current]
                                           human gate: review diff -> pin
    sudo pinned bless <repo> --tag <tag>   signature gate: verify signed tag -> pin
    pinned status <repo>
    pinned slot <repo>                     print the repo's pin-file path

Blessing history: `log show --predicate 'eventMessage CONTAINS "pinned:"'`

## Design points

- Pins live in /etc/pinned/<encoded-repo-path>, root:wheel 644, written
  atomically. Consumers that want a friendly path use a root-owned
  symlink: `sudo ln -s "$(pinned slot <repo>)" /etc/nix-darwin/pinned-rev`.
- First blessing of a repo shows the full tree (diff from the empty
  tree) unless `--trust-current` is passed, loudly.
- Signing is not pinned's job. Sign releases the normal way
  (`git tag -s v1.2.3`); `bless --tag` verifies such a tag against
  root-owned /etc/pinned/allowed_signers (git's native format). Any
  repo that already signs releases works with no pinned-specific
  conventions. That is the second-machine bootstrap: clone anywhere,
  install the signer key once (obtained out of band), bless the tag.
- Deploy consumers are separate scripts: pinned states trust, never
  acts on it.

Full design: ../claude-code-hardening/design/PLAN-pinned.md
Family: ../locked (setup/verify patterns reused), ../sudowhat.
