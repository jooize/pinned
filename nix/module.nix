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

      environment.systemPackages = [ package ];

      environment.etc."sudoers.d/pinned".source = sudoersFile;
    }

    # Per-user read-group `_<user>-pinned`, one per security.pinned.users
    # entry. pinned chgrp's /var/db/pinned/<user> to it BY NAME during
    # ceremonies and fails CLOSED to `0700 root` while it is absent (privacy
    # over availability), so provisioning belongs HERE, with the tool that
    # owns the tree -- a consumer module cannot be the thing every deployment
    # depends on for its own records to be readable.
    #
    # Per-OS split: NixOS declares the group (auto-allocated system gid);
    # nix-darwin's users.groups demands an explicit gid and has no allocator,
    # and an unpinned `dseditgroup -o create` may land a gid >=500 that the
    # login window would SHOW -- so Darwin scans for the lowest free gid in
    # the hidden 401..499 service range and creates imperatively (idempotent,
    # root, activation-time). Membership is asserted on every activation.
    (lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
      system.activationScripts.extraActivation.text = lib.mkAfter (lib.concatMapStrings (user: ''
        if ! /usr/bin/dscl . -read "/Groups/_${user}-pinned" PrimaryGroupID >/dev/null 2>&1; then
          taken="$(/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk '{print $2}')"
          pinned_gid=""
          for c in $(/usr/bin/seq 401 499); do
            if ! printf '%s\n' "$taken" | /usr/bin/grep -qx "$c"; then pinned_gid="$c"; break; fi
          done
          if [ -n "$pinned_gid" ]; then
            echo "creating group _${user}-pinned (gid $pinned_gid, hidden range)..." >&2
            /usr/sbin/dseditgroup -o create -i "$pinned_gid" -r ${lib.escapeShellArg "Root-owned pinned approval records ${user} may read"} "_${user}-pinned" || true
          else
            echo "creating group _${user}-pinned (no free gid in 401-499; auto)..." >&2
            /usr/sbin/dseditgroup -o create -r ${lib.escapeShellArg "Root-owned pinned approval records ${user} may read"} "_${user}-pinned" || true
          fi
        fi
        /usr/sbin/dseditgroup -o edit -a "${user}" -t user "_${user}-pinned" 2>/dev/null || true
      '') cfg.users);
    })
    (lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      users.groups = lib.listToAttrs (map (user: {
        name = "_${user}-pinned";
        value = { members = [ user ]; };
      }) cfg.users);
    })
  ]);
}
