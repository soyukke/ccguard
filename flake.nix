{
  description = "ccguard - lightweight Claude Code hook guard written in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "ccguard";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [ pkgs.zig ];
          buildPhase = ''
            zig build -Doptimize=ReleaseFast --prefix $out
          '';
          installPhase = "true";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.zig
            pkgs.zls
            pkgs.just
            pkgs.vhs
          ];
        };
      }
    );
}
