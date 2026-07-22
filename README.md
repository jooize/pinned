# pinned

Review-and-pin a git rev: `sudo pinned bless` shows the diff since the
last blessing from the object store, you approve (sudowhat dialog shows
the exact command), it writes the SHA to a root-owned pin file
(/etc/nix-darwin/pinned-rev). Deploy tooling builds only
`git+file://...?rev=<pinned sha>`. `pinned sign` optionally signs the
pinned tag (1Password SSH agent) for second-machine bootstrap.

## Commands

    sudo pinned setup                          self-install + digest-pinned sudoers
    sudo pinned bless <repo> [--pin-file <p>] [--trust-current]
    pinned sign <repo>                         no sudo -- needs your SSH agent
    pinned status <repo>
    pinned history

Pin files live in /etc/pinned/<encoded-repo-path> (root:wheel 644) by
default; `--pin-file` redirects a repo's pin to a consumer-specific path
(e.g. /etc/nix-darwin/pinned-rev) and records a `.link` back-reference so
status/sign still find it. First blessing of a repo shows the full tree
(diff from the empty tree) unless `--trust-current` is passed, loudly.

Deploy consumers are separate scripts: pinned states trust, never acts
on it.

Full design: ../claude-code-hardening/design/PLAN-pinned.md
Family: ../locked (setup/verify patterns reused), ../sudowhat.
