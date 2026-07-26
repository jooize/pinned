{
  description = "pinned -- review-and-pin a git rev behind a human gate";

  # No inputs: the module takes pkgs/lib from the consuming system.
  outputs = { self }: {
    darwinModules.default = import ./nix/module.nix;
    nixosModules.default = import ./nix/module.nix;
  };
}
