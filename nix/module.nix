# Declarative pinned install for nix-darwin and NixOS.
#
# Installs the pinned script into the system profile and writes a
# digest-pinned /etc/sudoers.d/pinned entry. Both derive from ONE string
# at eval time (scriptText below), so the sudoers digest and the
# installed binary can never disagree -- the drift window that manual
# `pinned setup` closes by re-running is structurally absent here.
#
# Conventional paths only: the binary lands in the system profile like
# any other package (environment.systemPackages); the sudoers line names
# the stable /run/current-system/sw/bin/pinned path, which survives
# generations and always resolves to the current build's bytes.
#
# Live-verify once per platform: sudo's Digest_Spec check must accept
# the profile path (a symlink chain into the store -- sudo hashes the
# file it resolves and executes). If a platform's sudo refuses, point
# installPath at a real file installed by other means; do not weaken
# the digest.
{ config, lib, pkgs, ... }:

let
  cfg = config.security.pinned;

  srcText = builtins.readFile ../pinned;

  # The script self-elevates by re-exec'ing $INSTALL_TARGET, and its
  # trusted PATH carries only the OS's root-owned directories -- each
  # packaging prepends its own root-owned prefix. Rewrite those anchor
  # lines to this module's configuration, and fail the eval loudly if
  # any anchor ever changes shape in the script.
  anchors = [
    {
      # sudo passes the caller's full PATH through (probed live
      # 2026-08-06 on the reference Mac: `sudo printenv PATH` returned
      # the user's complete PATH), and env resolves the interpreter from
      # it BEFORE the script's own PATH export runs -- so `env bash`
      # would let the invoker's environment pick root's interpreter. Pin
      # it to the store bash: root-owned, immutable, present on both
      # platforms. (locked pins /bin/bash instead; that tool is
      # Darwin-only and targets the SIP-sealed system bash.)
      from = "#!/usr/bin/env bash";
      to = "#!${pkgs.bash}/bin/bash";
    }
    {
      from = '': "''${INSTALL_TARGET:=/usr/local/sbin/pinned}"'';
      to = '': "''${INSTALL_TARGET:=${cfg.installPath}}"'';
    }
    {
      # The system profile is a root-owned symlink farm into /nix/store
      # (changing it needs root, same as /usr/bin); it goes first so a
      # machine with a newer git/coreutils uses them.
      from = "export PATH=/usr/bin:/bin:/usr/sbin:/sbin";
      to = "export PATH=/run/current-system/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin";
    }
  ];
  scriptText =
    assert lib.assertMsg (lib.all (a: lib.hasInfix a.from srcText) anchors)
      "pinned/nix: an anchor line was not found in ../pinned; update module.nix";
    builtins.replaceStrings (map (a: a.from) anchors) (map (a: a.to) anchors) srcText;

  package = pkgs.writeScriptBin "pinned" scriptText;

  # The man page is its own store path, deliberately outside scriptText:
  # documentation edits must never move the sudoers digest.
  manPage = pkgs.runCommand "pinned-man" { } ''
    install -D -m 444 ${../man/pinned.1} $out/share/man/man1/pinned.1
  '';

  digest = builtins.hashString "sha256" scriptText;

  sudoersText = lib.concatMapStrings
    (user: "${user} ALL=(root) sha256:${digest} ${cfg.installPath}\n")
    cfg.users;

  # Syntax-check with visudo where the sudo package builds (Linux); a
  # malformed sudoers.d file can lock sudo out entirely. On Darwin the
  # generated line is the only content and users are shape-asserted
  # below, so the residual risk is the fixed template itself.
  sudoersFile =
    if pkgs.stdenv.hostPlatform.isLinux then
      pkgs.runCommand "sudoers-pinned"
        { nativeBuildInputs = [ pkgs.sudo ]; }
        ''
          printf '%s' ${lib.escapeShellArg sudoersText} > pinned
          visudo -c -f pinned
          install -m 444 pinned $out
        ''
    else
      pkgs.writeText "sudoers-pinned" sudoersText;

  validUser = user: builtins.match "[A-Za-z_][A-Za-z0-9_-]*" user != null;

  # The operators group of the shared clone tree `pinned add` fetches into
  # (/var/db/pinned-clones). ONE literal spelling, matching the script's
  # PINNED_CLONES_GROUP constant -- the script consumes this group by name
  # and degrades to an invoker-owned clone while it is absent.
  #
  # The DIRECTORY is deliberately not created here: the script provisions it
  # root-side at the first add, so a manual install lands on the same path
  # with the same ownership. Only the group, which no script may create.
  clonesGroup = "_pinned-clones";

  # Darwin has no gid allocator: users.groups demands an explicit gid, and an
  # unpinned `dseditgroup -o create` may land a gid >=500 that the login
  # window would SHOW. So scan for the lowest free gid in the hidden 401..499
  # service range and create imperatively (idempotent, root, activation-time);
  # membership is asserted on every activation. One emitter for both the
  # per-user read groups and the shared clone-tree group -- the two differ
  # only in name, purpose and who belongs to them.
  darwinGroup = { name, comment, members }: ''
    if ! /usr/bin/dscl . -read "/Groups/${name}" PrimaryGroupID >/dev/null 2>&1; then
      taken="$(/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk '{print $2}')"
      pinned_gid=""
      for c in $(/usr/bin/seq 401 499); do
        if ! printf '%s\n' "$taken" | /usr/bin/grep -qx "$c"; then pinned_gid="$c"; break; fi
      done
      if [ -n "$pinned_gid" ]; then
        echo "creating group ${name} (gid $pinned_gid, hidden range)..." >&2
        /usr/sbin/dseditgroup -o create -i "$pinned_gid" -r ${lib.escapeShellArg comment} "${name}" || true
      else
        echo "creating group ${name} (no free gid in 401-499; auto)..." >&2
        /usr/sbin/dseditgroup -o create -r ${lib.escapeShellArg comment} "${name}" || true
      fi
    fi
  '' + lib.concatMapStrings (user: ''
    /usr/sbin/dseditgroup -o edit -a "${user}" -t user "${name}" 2>/dev/null || true
  '') members;
in
{
  options.security.pinned = {
    enable = lib.mkEnableOption "pinned, the review-and-pin trust gate";

    users = lib.mkOption {
      type = with lib.types; listOf str;
      description = ''
        Users granted sudo for the pinned binary, digest-pinned to the
        installed bytes. No NOPASSWD: sudo still authenticates.
      '';
    };

    installPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/current-system/sw/bin/pinned";
      description = ''
        Path this module's sudoers entry names and that the installed
        script re-execs for self-elevation; it must be the path actually
        invoked under sudo. The default is the system-profile path, which
        is stable across generations and always resolves to the current
        build. (Manual, non-nix installs are unaffected by this option:
        they use the script's own default, /usr/local/sbin/pinned.)
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      default = package;
      defaultText = lib.literalMD "the script this module installs";
      description = ''
        The pinned package this module builds and installs, exposed so a
        consumer can hand the SAME derivation to something that needs its
        own copy -- a container image, a VM guest flake -- without
        rebuilding it from source.

        Read-only on purpose: these are the bytes the sudoers Digest_Spec
        commits to, so a consumer's copy is byte-identical to the
        installed one by construction rather than by convention. Rebuilding
        it independently would reintroduce exactly the drift window this
        module's single-scriptText design exists to close, and a copy whose
        `installPath` anchor disagreed would re-exec a path that does not
        exist when it self-elevates.
      '';
    };

  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.users != [ ];
          message = "security.pinned.users must name at least one user";
        }
        {
          assertion = lib.all validUser cfg.users;
          message = "security.pinned.users: user names must match [A-Za-z_][A-Za-z0-9_-]* (they are spliced into sudoers)";
        }
      ];

      environment.systemPackages = [ package manPage ];

      environment.etc."sudoers.d/pinned".source = sudoersFile;
    }

    # Two kinds of group, both CONSUMED by the script and created only here.
    #
    # Per-user read-group `_<user>-pinned`, one per security.pinned.users
    # entry. pinned chgrp's /var/db/pinned/<user> to it BY NAME during
    # ceremonies and fails CLOSED to `0700 root` while it is absent (privacy
    # over availability), so provisioning belongs HERE, with the tool that
    # owns the tree -- a consumer module cannot be the thing every deployment
    # depends on for its own records to be readable.
    #
    # Operators group `_pinned-clones`, one per machine, holding every
    # configured user: it owns the shared clone tree, so any of them can
    # fetch into a clone another one made. Its absence is not a privacy
    # question -- content addressing gates trust either way -- so the script
    # degrades to an invoker-owned clone instead of refusing.
    #
    # Per-OS split: NixOS declares groups (auto-allocated system gids);
    # Darwin creates them imperatively at activation (see darwinGroup).
    (lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
      system.activationScripts.extraActivation.text = lib.mkAfter (
        lib.concatMapStrings
          (user: darwinGroup {
            name = "_${user}-pinned";
            comment = "Root-owned pinned approval records ${user} may read";
            members = [ user ];
          })
          cfg.users
        + darwinGroup {
          name = clonesGroup;
          comment = "Operators of the shared pinned clone tree";
          members = cfg.users;
        });
    })
    (lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      users.groups = lib.listToAttrs (map (user: {
        name = "_${user}-pinned";
        value = { members = [ user ]; };
      }) cfg.users) // {
        ${clonesGroup} = { members = cfg.users; };
      };
    })
  ]);
}
