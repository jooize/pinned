# pinned

Review-and-pin a git rev: `sudo pinned bless` shows the diff since the
last blessing from the object store, you approve (sudowhat dialog shows
the exact command), it writes the SHA to a root-owned pin file
(/etc/nix-darwin/pinned-rev). Deploy tooling builds only
`git+file://...?rev=<pinned sha>`. `pinned sign` optionally signs the
pinned tag (1Password SSH agent) for second-machine bootstrap.

NOT IMPLEMENTED YET. Full design:
../claude-code-hardening/design/PLAN-pinned.md
Family: ../locked (reuse its setup/verify patterns), ../sudowhat.
