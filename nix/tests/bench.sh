#!/usr/bin/env bash
# performance benchmark for railscale NixOS integration tests
#
# times each test variant via nix build --rebuild (forces fresh execution)
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
echo "  railscale NixOS test benchmark (attest/firecracker)"
echo -e "=======================================================================${RESET}"
echo ""

echo -e "${BOLD}--- warm-up (populating nix store) ---${RESET}"
warmup "module-smoke"            ".#module-smoke"
warmup "module-smoke (snapshot)" ".#module-smoke-snapshot"
warmup "policy-reload"           ".#checks.x86_64-linux.nixos-test-policy"
warmup "policy-reload (snapshot)" ".#policy-reload-snapshot"
warmup "cli-integration"         ".#checks.x86_64-linux.nixos-test"
warmup "cli-integration (snapshot)" ".#cli-integration-snapshot"
echo ""

echo -e "${BOLD}--- module-smoke (4 VMs) ---${RESET}"
time_test "cold boot"  ".#module-smoke"          smoke
time_test "snapshot"   ".#module-smoke-snapshot"  smoke_snap
echo ""

echo -e "${BOLD}--- policy-reload (1 VM) ---${RESET}"
time_test "cold boot"  ".#checks.x86_64-linux.nixos-test-policy" policy
time_test "snapshot"   ".#policy-reload-snapshot"                 policy_snap
echo ""

echo -e "${BOLD}--- cli-integration (3 VMs, full suite) ---${RESET}"
time_test "cold boot"  ".#checks.x86_64-linux.nixos-test"  cli
time_test "snapshot"   ".#cli-integration-snapshot"         cli_snap
echo ""

smoke=$(cat "$TMPDIR/smoke")
smoke_snap=$(cat "$TMPDIR/smoke_snap")
policy=$(cat "$TMPDIR/policy")
policy_snap=$(cat "$TMPDIR/policy_snap")
cli=$(cat "$TMPDIR/cli")
cli_snap=$(cat "$TMPDIR/cli_snap")

speedup() {
  local base="$1" fast="$2"
  if [ "$fast" -gt 0 ]; then
    local whole=$(( base / fast ))
    local frac=$(( (base * 10 / fast) % 10 ))
    local ratio="${whole}.${frac}"
    if [ "$base" -gt "$fast" ]; then
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
printf "  %-30s %8s %10s %8s\n" "test" "cold" "snapshot" "speedup"
printf "  %-30s %8s %10s %8s\n" "------------------------------" "--------" "----------" "--------"
printf "  %-30s %7ds %9ds   %b\n" "module-smoke (4 VMs)"    "$smoke"  "$smoke_snap"  "$(speedup "$smoke" "$smoke_snap")"
printf "  %-30s %7ds %9ds   %b\n" "policy-reload (1 VM)"    "$policy" "$policy_snap" "$(speedup "$policy" "$policy_snap")"
printf "  %-30s %7ds %9ds   %b\n" "cli-integration (3 VMs)" "$cli"    "$cli_snap"    "$(speedup "$cli" "$cli_snap")"

total=$(( smoke + policy + cli ))
total_snap=$(( smoke_snap + policy_snap + cli_snap ))
printf "  ${BOLD}%-30s %7ds %9ds   %b${RESET}\n" "TOTAL" "$total" "$total_snap" "$(speedup "$total" "$total_snap")"
echo ""
