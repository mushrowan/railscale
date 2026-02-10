# Railscale package build using crane
#
# Usage:
#   packageSet = import ./package.nix { inherit pkgs craneLib; };
#   inherit (packageSet) railscale cargoArtifacts commonArgs;
{
  pkgs,
  craneLib,
  src ? null,
}:
let
  # Common source filtering - include proto files for tonic-build
  protoFilter = path: _type: builtins.match ".*\\.proto$" path != null;
  filteredSrc = pkgs.lib.cleanSourceWith {
    src = ../.;
    filter = path: type: (protoFilter path type) || (craneLib.filterCargoSources path type);
  };

  # Use provided src or default filtered source
  finalSrc = if src != null then src else filteredSrc;

  # Common arguments for all builds
  commonArgs = {
    src = finalSrc;
    strictDeps = true;

    nativeBuildInputs = with pkgs; [
      pkg-config
      protobuf # For tonic-build (gRPC)
    ];

    buildInputs =
      with pkgs;
      [
        cacert # CA certificates for TLS in tests
      ]
      ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
        pkgs.darwin.apple_sdk.frameworks.Security
        pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
      ];
  };

  # Build just the cargo dependencies for caching
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # Build the actual package
  railscale = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      meta.mainProgram = "railscale";
    }
  );
in
{
  inherit
    railscale
    cargoArtifacts
    commonArgs
    ;
}
