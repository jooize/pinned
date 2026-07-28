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

  # pinned-deploy: the deploy consumer (separate program -- pinned states
  # trust, never acts on it). Same PATH anchor; no INSTALL_TARGET (it does
  # not self-elevate) and no sudoers digest (it is not the trust gate --
  # it composes and shows commands that run under ordinary sudo).
  pathAnchor = builtins.elemAt anchors 1;
  deploySrcText = builtins.readFile ../pinned-deploy;
  deployText =
    assert lib.assertMsg (lib.hasInfix pathAnchor.from deploySrcText)
      "pinned/nix: the PATH anchor line was not found in ../pinned-deploy; update module.nix";
    builtins.replaceStrings [ pathAnchor.from ] [ pathAnchor.to ] deploySrcText;

  deployPackage = pkgs.writeScriptBin "pinned-deploy" deployText;

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

  config = lib.mkIf cfg.enable {
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

    environment.systemPackages = [ package deployPackage ];

    environment.etc."sudoers.d/pinned".source = sudoersFile;
  };
}
