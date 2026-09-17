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
      # Both spellings pin the interpreter absolutely; this only swaps
      # which absolute one. sudo passes the caller's full PATH through
      # (probed live 2026-08-06 on the reference Mac: `sudo printenv
      # PATH` returned the user's complete PATH), and env would resolve
      # the interpreter from it BEFORE the script's own PATH export runs
      # -- so an `env bash` shebang would let the invoker's environment
      # pick root's interpreter. The source therefore ships /bin/bash,
      # root-owned on stock macOS and stock Linux; NixOS has no
      # /bin/bash, so the module points the line at the store bash:
      # root-owned, immutable, present on both platforms.
      from = "#!/bin/bash";
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
    {
      # The accounts whose files verify's owner invariant admits alongside
      # root (see the constant's comment in the script). Baked here rather
      # than read at run time, so the only thing that can widen the
      # invariant is the build that also created the account.
      #
      # Anchored on the WHOLE line, newlines included: `PINNED_ROOT_ONLY_OWNERS=`
      # on its own is a prefix of the very line this rewrite produces, so the
      # hasInfix assertion below would keep passing after a rewrite and
      # replaceStrings would hit the assignment inside the script's own
      # comment block just as happily. The surrounding newlines make the
      # match exactly one line, and only while it is still empty.
      from = "\nPINNED_ROOT_ONLY_OWNERS=\n";
      to = "\nPINNED_ROOT_ONLY_OWNERS=${lib.concatStringsSep " " cfg.rootOnlyOwners}\n";
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

  # Every group this module owns, one definition feeding both provisioning
  # modes and both platforms: one read group per configured user.
  allGroups =
    map (user: {
      name = "_${user}-pinned";
      comment = "Root-owned pinned approval records ${user} may read";
      members = [ user ];
    }) cfg.users;
  declaredGroups = builtins.filter (g: cfg.gids ? ${g.name}) allGroups;
  imperativeGroups = builtins.filter (g: !(cfg.gids ? ${g.name})) allGroups;

  # Darwin has no gid allocator: users.groups demands an explicit gid, and an
  # unpinned `dseditgroup -o create` may land a gid >=500 that the login
  # window would SHOW. So, unless a group's gid is pinned via cfg.gids,
  # scan for the lowest free gid in the hidden 401..499 service range and
  # create imperatively (idempotent, root, activation-time); membership is
  # asserted on every activation.
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

    gids = lib.mkOption {
      type = lib.types.attrsOf lib.types.int;
      default = { };
      example = lib.literalExpression ''{ "_alice-pinned" = 411; }'';
      description = ''
        Optional fixed gids, keyed by group name (the per-user read
        groups _<user>-pinned).
        A group named here is declared via users.groups/knownGroups with
        exactly this gid -- the preferred, declarative mode: the numbers
        live in the config, and on-disk group ownership keeps its
        meaning across any recreation. On Darwin every managed group
        must either appear here or be covered by allocateIds = true.
        Deletion is a manual ceremony either way: nix-darwin refuses to
        delete accounts with ids <= 501.
      '';
    };

    allocateIds = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow groups NOT named in gids to get an allocated id -- the
        explicit opt-out for a config that must not carry
        machine-specific numbers, never a silent fallback. On Darwin
        that means imperative creation at activation with the first
        free gid in 401-499; on NixOS the system allocator already does
        this for numberless declared groups, so the option is not
        required there. (One option name, allocateIds, across this
        module family -- see security.locked.allocateIds.)
      '';
    };

    rootOnlyOwners = lib.mkOption {
      type = with lib.types; listOf str;
      default = [ ];
      example = lib.literalExpression ''[ "_alice-lock" ]'';
      description = ''
        Accounts that no user can act as -- no shell, no password, no
        service -- whose files therefore pass verify's owner invariant
        the way root-owned ones do: the tier user cannot rewrite them
        either. Baked into the installed bytes at eval time, so the
        sudoers digest covers the list and nothing at run time can widen
        the invariant.

        Contributed by the module of whichever tool CREATES such an
        account, never typed by hand: security.locked adds its per-user
        lock account _<user>-lock here. A machine that declares no such
        tool keeps the empty default, and pinned refuses a file owned by
        an account it was never told about.
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
        {
          # Same shape as a user name, and for a stronger reason: these are
          # spliced into a script line that the sudoers digest then commits
          # to, so a name carrying a space would silently split into two
          # entries and one carrying shell metacharacters would be baked
          # into the installed bytes verbatim.
          assertion = lib.all validUser cfg.rootOnlyOwners;
          message = "security.pinned.rootOnlyOwners: account names must match [A-Za-z_][A-Za-z0-9_-]* (they are spliced into the installed script)";
        }
        {
          # A stray key would otherwise be a silent no-op while its group
          # still gets an imperative first-free gid.
          assertion = lib.all (n: lib.any (g: g.name == n) allGroups) (lib.attrNames cfg.gids);
          message = "security.pinned.gids names a group this module does not manage (expected _<user>-pinned for a configured user)";
        }
        {
          # Declarative is the default expectation (the config carries
          # the numbers); imperative allocation is an explicit opt-out.
          assertion = !pkgs.stdenv.hostPlatform.isDarwin
            || cfg.allocateIds
            || lib.all (g: cfg.gids ? ${g.name}) allGroups;
          message = "security.pinned: on Darwin declare every managed group in gids (declarative, preferred) or set allocateIds = true for first-free allocation of the rest";
        }
      ];

      environment.systemPackages = [ package manPage ];

      environment.etc."sudoers.d/pinned".source = sudoersFile;
    }

    # The groups the script CONSUMES, created only here.
    #
    # Per-user read-group `_<user>-pinned`, one per security.pinned.users
    # entry. pinned chgrp's /var/db/pinned/<user> to it BY NAME during
    # ceremonies and fails CLOSED to `0700 root` while it is absent (privacy
    # over availability), so provisioning belongs HERE, with the tool that
    # owns the tree -- a consumer module cannot be the thing every deployment
    # depends on for its own records to be readable.
    #
    # Per-OS split: NixOS declares groups (auto-allocated system gids);
    # Darwin creates them imperatively at activation (see darwinGroup).
    (lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
      users.knownGroups = map (g: g.name) declaredGroups;
      users.groups = lib.listToAttrs (map (g: {
        name = g.name;
        value = {
          gid = cfg.gids.${g.name};
          description = g.comment;
          members = g.members;
        };
      }) declaredGroups);
      system.activationScripts.extraActivation.text = lib.mkAfter
        (lib.concatMapStrings darwinGroup imperativeGroups);
    })
    (lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      # NixOS allocates system gids itself; a declared gid just pins it.
      users.groups = lib.listToAttrs (map (g: {
        name = g.name;
        value = { members = g.members; }
          // lib.optionalAttrs (cfg.gids ? ${g.name}) { gid = cfg.gids.${g.name}; };
      }) allGroups);
    })
  ]);
}
