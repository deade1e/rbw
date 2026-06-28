{
  description = "rbw: unofficial bitwarden cli";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    {

      packages.aarch64-linux.hello = nixpkgs.legacyPackages.aarch64-linux.hello;

      packages.aarch64-linux.default = self.packages.aarch64-linux.hello;
      devShells.aarch64-linux.default = import ./shell.nix {
        pkgs = nixpkgs.legacyPackages.aarch64-linux;
      };

    };
}
