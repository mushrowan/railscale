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
      # For now only build for current arch, to silence `nix flake check` warnings
      systems = ["x86_64-linux"];
      # systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

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
            meta.mainProgram = "railscale";
          });
      in {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [(import inputs.rust-overlay)];
        };

        checks = let
          clippyBase = x:
            craneLib.cargoClippy (commonArgs
              // {
                inherit cargoArtifacts;
              })
            // x;
        in
          {
            inherit railscale;

            # Run clippy
            clippy = clippyBase {cargoClippyExtraArgs = "--all-targets";};
            clippyDenyWarnings = clippyBase {cargoClippyExtraArgs = "--all-targets -- --deny warnings";};

            # Check formatting
            fmt = craneLib.cargoFmt {
              inherit src cargoArtifacts;
            };
            cargoTest = craneLib.cargoTest (commonArgs // {inherit cargoArtifacts;});
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # NixOS integration tests (Linux only)
            nixos-test = import ./tests.nix {
              inherit pkgs;
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

            # Run the NixOS VM integration test with full logs
            (writeShellScriptBin "vmtest" ''
              set -e
              echo "=== Running NixOS VM integration test ==="
              nix build .#checks.x86_64-linux.nixos-test --print-build-logs --rebuild "$@"
              echo "=== VM test passed! ==="
            '')

            # Run nix flake check with full logs
            (writeShellScriptBin "check-verbose" ''
              set -e
              echo "=== check-verbose: Build all flake checks with full logs ==="
              echo ""
              echo "Cached builds show no logs. To force rebuild and see logs:"
              echo "  check-verbose --rebuild    (may fail on non-deterministic derivations)"
              echo "  nix build .#checks.x86_64-linux.nixos-test -L --rebuild"
              echo ""
              
              # Get system architecture
              system=$(nix eval --impure --raw --expr 'builtins.currentSystem')
              
              # Get list of checks for this system
              checks=$(nix eval ".#checks.$system" --apply 'builtins.attrNames' --json | ${pkgs.jq}/bin/jq -r '.[]')
              
              # Build each check with verbose logging
              for check in $checks; do
                echo "=== Building: $check ==="
                nix build ".#checks.$system.$check" \
                  --no-link \
                  --print-build-logs \
                  "$@" || { echo "FAILED: $check"; exit 1; }
              done
              
              echo ""
              echo "=== All checks passed! ==="
            '')
          ];

          RUST_LOG = "railscale=debug";
        };
      };
    };
}
