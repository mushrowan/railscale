# Development shell for railscale
#
# Usage:
#   devShells.default = import ./nix/devshell.nix { inherit pkgs craneLib checks; };
{
  pkgs,
  craneLib,
  checks ? { },
}:
craneLib.devShell {
  inherit checks;

  packages = with pkgs; [
    cargo-edit
    cargo-llvm-cov
    cargo-update

    curl
    jq
    protobuf # For tonic-build (gRPC)

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
      checks=$(nix eval ".#checks.$system" --apply 'builtins.attrNames' --json | ${jq}/bin/jq -r '.[]')

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
}
