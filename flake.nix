{
  description = "tailscale control server written in rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      crane,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
      ];

      systems = [ "x86_64-linux" ];

      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          # Import package build
          packageSet = import ./nix/package.nix { inherit pkgs craneLib; };
          inherit (packageSet) railscale cargoArtifacts commonArgs;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
          };

          checks =
            let
              clippyBase =
                x:
                craneLib.cargoClippy (
                  commonArgs
                  // {
                    inherit cargoArtifacts;
                  }
                )
                // x;
            in
            {
              inherit railscale;

              clippy = clippyBase { cargoClippyExtraArgs = "--all-targets"; };
              clippyDenyWarnings = clippyBase { cargoClippyExtraArgs = "--all-targets -- --deny warnings"; };

              fmt = craneLib.cargoFmt {
                inherit (commonArgs) src;
                inherit cargoArtifacts;
              };
              cargoTest = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
              # NixOS integration tests (Linux only)
              nixos-test = import ./nix/tests/cli-integration.nix {
                inherit pkgs railscale;
              };
              nixos-test-policy = import ./nix/tests/policy-reload.nix {
                inherit pkgs railscale;
              };
            };

          packages = {
            default = railscale;
            inherit railscale;
          };

          devShells.default = import ./nix/devshell.nix {
            inherit pkgs craneLib;
            checks = self'.checks;
          };

          # treefmt configuration for `nix fmt`
          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              nixfmt.enable = true;
              rustfmt = {
                enable = true;
                package = rustToolchain;
              };
              taplo.enable = true;
            };
          };
        };

      # Flake-wide outputs (not per-system)
      flake = self: {
        nixosModules = rec {
          railscale =
            { pkgs, ... }:
            {
              imports = [ ./nix/module.nix ];
              services.railscale.package = self.packages.${pkgs.stdenv.hostPlatform.system}.railscale;
            };
          default = railscale;
        };
      };
    };
}
