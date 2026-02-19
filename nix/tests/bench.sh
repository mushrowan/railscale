#!/usr/bin/env bash
# performance comparison: python/QEMU vs elixir/firecracker
#
# times each test pair via nix build --rebuild (forces fresh VM execution)
# does a warm-up build first so --rebuild has something to invalidate
#
# usage: ./nix/tests/bench.sh
set -euo pipefail

BOLD=$'\033[1m'
DIM=$'\033[2m'
CYAN=$'\033[36m'
GREEN=$'\033[32m'
RED=$'\033[31m'
RESET=$'\033[0m'

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

warmup() {
  local label="$1" attr="$2"
  printf "  %swarm-up: %s%s" "$DIM" "$label" "$RESET"
  if nix build "$attr" --no-link 2>/dev/null; then
    printf "\r  %swarm-up: %s ✓%s\n" "$DIM" "$label" "$RESET"
  else
    printf "\r  %swarm-up: %s ✗ (building from scratch)%s\n" "$DIM" "$label" "$RESET"
    nix build "$attr" --no-link -L 2>/dev/null
  fi
}

time_test() {
  local label="$1" attr="$2" outvar="$3"
  local start end elapsed

  start=$(date +%s)
  printf "  %s%-35s%s " "$DIM" "$label" "$RESET"
  nix build "$attr" --rebuild --no-link 2>/dev/null
  end=$(date +%s)
  elapsed=$(( end - start ))
  printf "\r  %s%-35s%s %s%4ds%s\n" "$CYAN" "$label" "$RESET" "$BOLD" "$elapsed" "$RESET"
  echo "$elapsed" > "$TMPDIR/$outvar"
}

echo ""
echo -e "${BOLD}======================================================================="
echo "  railscale test performance: python/QEMU vs elixir/firecracker"
echo -e "=======================================================================${RESET}"
echo ""

# warm-up: ensure all outputs exist so --rebuild works
echo -e "${BOLD}--- warm-up (populating nix store) ---${RESET}"
warmup "module-smoke (python)" ".#module-smoke-test"
warmup "module-smoke (attest)" ".#module-smoke-attest"
warmup "policy-reload (python)" ".#checks.x86_64-linux.nixos-test-policy"
warmup "policy-reload (attest)" ".#policy-reload-attest"
warmup "cli-integration (python)" ".#checks.x86_64-linux.nixos-test"
warmup "cli-integration (attest)" ".#cli-integration-attest"
echo ""

echo -e "${BOLD}--- module-smoke (4 VMs) ---${RESET}"
time_test "python/QEMU" ".#module-smoke-test" smoke_py
time_test "elixir/firecracker" ".#module-smoke-attest" smoke_ex
echo ""

echo -e "${BOLD}--- policy-reload (1 VM) ---${RESET}"
time_test "python/QEMU" ".#checks.x86_64-linux.nixos-test-policy" policy_py
time_test "elixir/firecracker" ".#policy-reload-attest" policy_ex
echo ""

echo -e "${BOLD}--- cli-integration (3 VMs, full suite) ---${RESET}"
time_test "python/QEMU" ".#checks.x86_64-linux.nixos-test" cli_py
time_test "elixir/firecracker" ".#cli-integration-attest" cli_ex
echo ""

smoke_py=$(cat "$TMPDIR/smoke_py")
smoke_ex=$(cat "$TMPDIR/smoke_ex")
policy_py=$(cat "$TMPDIR/policy_py")
policy_ex=$(cat "$TMPDIR/policy_ex")
cli_py=$(cat "$TMPDIR/cli_py")
cli_ex=$(cat "$TMPDIR/cli_ex")

speedup() {
  local py="$1" ex="$2"
  if [ "$ex" -gt 0 ]; then
    # python/attest ratio with one decimal
    local whole=$(( py / ex ))
    local frac=$(( (py * 10 / ex) % 10 ))
    local ratio="${whole}.${frac}"
    if [ "$py" -gt "$ex" ]; then
      echo "${GREEN}${ratio}x${RESET}"
    else
      echo "${RED}${ratio}x${RESET}"
    fi
  else
    echo "?"
  fi
}

echo -e "${BOLD}======================================================================="
echo "  summary"
echo -e "=======================================================================${RESET}"
printf "  %-25s %8s %8s %8s\n" "test" "python" "attest" "speedup"
printf "  %-25s %8s %8s %8s\n" "-------------------------" "--------" "--------" "--------"
printf "  %-25s %7ds %7ds   %b\n" "module-smoke" "$smoke_py" "$smoke_ex" "$(speedup "$smoke_py" "$smoke_ex")"
printf "  %-25s %7ds %7ds   %b\n" "policy-reload" "$policy_py" "$policy_ex" "$(speedup "$policy_py" "$policy_ex")"
printf "  %-25s %7ds %7ds   %b\n" "cli-integration" "$cli_py" "$cli_ex" "$(speedup "$cli_py" "$cli_ex")"

total_py=$(( smoke_py + policy_py + cli_py ))
total_ex=$(( smoke_ex + policy_ex + cli_ex ))
printf "  ${BOLD}%-25s %7ds %7ds   %b${RESET}\n" "TOTAL" "$total_py" "$total_ex" "$(speedup "$total_py" "$total_ex")"
echo ""
