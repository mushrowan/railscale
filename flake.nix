{
  description = "tailscale control server written in rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
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
    attest = {
      url = "git+file:///home/rowan/dev/nixos-test-ng";
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

          # Static musl build
          muslRustToolchain = pkgs.rust-bin.stable.latest.default.override {
            targets = [ "x86_64-unknown-linux-musl" ];
          };
          pkgsMusl = pkgs.pkgsCross.musl64;
          craneMusl = (crane.mkLib pkgsMusl).overrideToolchain muslRustToolchain;
          muslPackageSet = import ./nix/package.nix {
            pkgs = pkgsMusl;
            craneLib = craneMusl;
          };
          railscaleStatic = muslPackageSet.railscale;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              (import inputs.rust-overlay)
              # workaround: lix now handles ssl-cert-file properly, but nixpkgs still
              # passes NIX_SSL_CERT_FILE as impure env var causing warnings
              # https://git.lix.systems/lix-project/lix/commit/2d0109898a65884e8953813c0391ad8b3be0d929
              (final: prev: {
                lib = prev.lib // {
                  fetchers = prev.lib.fetchers // {
                    proxyImpureEnvVars = builtins.filter (
                      v: v != "NIX_SSL_CERT_FILE"
                    ) prev.lib.fetchers.proxyImpureEnvVars;
                  };
                };
              })
            ];
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

              # note: cargoFmt clears cargoArtifacts/cargoVendorDir by design (no compilation needed)
              fmt = craneLib.cargoFmt { inherit (commonArgs) src; };
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
            inherit railscale railscaleStatic;

            # release tarball with static musl binary
            railscale-tarball =
              pkgs.runCommand "railscale-${railscaleStatic.version}-x86_64-linux-musl.tar.gz" { }
                ''
                  mkdir -p railscale-${railscaleStatic.version}
                  cp ${railscaleStatic}/bin/railscale railscale-${railscaleStatic.version}/
                  tar czf $out -C . railscale-${railscaleStatic.version}
                '';

            # OCI container image, pipe to docker/podman load:
            #   nix build .#docker && ./result | docker load
            docker = pkgs.dockerTools.streamLayeredImage {
              name = "railscale";
              tag = "latest";
              contents = [
                railscale
                pkgs.dockerTools.caCertificates
              ];
              config = {
                Entrypoint = [ "${railscale}/bin/railscale" ];
                Cmd = [ "serve" ];
                ExposedPorts = {
                  "8080/tcp" = { };
                  "3478/udp" = { };
                };
                Env = [
                  "RAILSCALE_LISTEN_ADDR=0.0.0.0:8080"
                ];
              };
            };

            # Smoke test for NixOS module options (not in checks, run manually)
            # Usage: nix build .#module-smoke-test -L
            module-smoke-test = import ./nix/tests/module-smoke.nix {
              inherit pkgs railscale;
            };
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # attest/firecracker versions of NixOS tests (~2x faster boot)
            module-smoke-attest = import ./nix/tests/module-smoke-attest.nix {
              inherit pkgs railscale;
              attest = inputs.attest.packages.${pkgs.system}.default;
              attestSrc = inputs.attest;
            };
            policy-reload-attest = import ./nix/tests/policy-reload-attest.nix {
              inherit pkgs railscale;
              attest = inputs.attest.packages.${pkgs.system}.default;
              attestSrc = inputs.attest;
            };
            cli-integration-attest = import ./nix/tests/cli-integration-attest.nix {
              inherit pkgs railscale;
              attest = inputs.attest.packages.${pkgs.system}.default;
              attestSrc = inputs.attest;
            };
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
      flake = {
        nixosModules = rec {
          railscale =
            { pkgs, ... }:
            {
              imports = [ ./nix/module.nix ];
              services.railscale.package = inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.railscale;
            };
          default = railscale;
        };
      };
    };
}
