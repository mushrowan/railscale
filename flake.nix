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
  };

  outputs = inputs @ {
    flake-parts,
    crane,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      debug = true; # <--- Add this line temporarily

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        
        ...
      }: let
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rust-src" "rust-analyzer"];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common source filtering
        src = craneLib.cleanCargoSource ./.;

        # Common arguments for all builds
        commonArgs = {
          inherit src;
          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs;
            [
              openssl
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
        };

        # Build just the cargo dependencies for caching
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual package
        railscale = craneLib.buildPackage (commonArgs
          // {
            inherit cargoArtifacts;
              # meta.mainProgram = name;
          });
      in {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [(import inputs.rust-overlay)];
        };

        checks =
          {
            inherit railscale;

            # Run clippy
            clippy = craneLib.cargoClippy (commonArgs
              // {
                inherit cargoArtifacts;
                # cargoClippyExtraArgs = "--all-targets -- --deny warnings";
                cargoClippyExtraArgs = "--all-targets -- --deny warnings";
              });

            # Check formatting
            fmt = craneLib.cargoFmt {
              inherit src;
            };
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # NixOS integration tests (Linux only)
            nixos-test = import ./tests.nix {
              inherit pkgs;
              inherit (pkgs) lib;
              railscale = railscale;
            };
          };

        packages = {
          default = railscale;
          inherit railscale;
        };

        devShells.default = craneLib.devShell {
          checks = self'.checks;

          packages = with pkgs; [
            cargo-update
            cargo-edit
            curl
            jq
          ];

          RUST_LOG = "railscale=debug";
        };
      };
    };
}
