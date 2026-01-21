# Policy Hot-Reload Tests for railscale
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Tests:
# 1. SIGHUP-based policy reload via systemctl reload
# 2. CLI-based policy reload via `railscale policy reload`
# 3. Policy get/set via CLI

import json
import time

start_all()

# =============================================================================
# PHASE 1: Server Startup
# =============================================================================
with subtest("Server starts successfully"):
    wait_for_server()
    print("Server started successfully")

wait_for_network()

# =============================================================================
# PHASE 2: Initial Policy Check
# =============================================================================
with subtest("Get initial policy"):
    output = railscale("policy get")
    policy = json.loads(output)
    
    # Verify initial policy structure
    assert "grants" in policy, "Policy should have grants"
    assert "groups" in policy, "Policy should have groups"
    
    initial_grants = len(policy["grants"])
    print(f"Initial policy has {initial_grants} grants")
    print(f"Groups: {list(policy['groups'].keys())}")

# =============================================================================
# PHASE 3: SIGHUP Policy Reload
# =============================================================================
with subtest("Update policy file"):
    # Write a new policy with an additional grant
    new_policy = {
        "groups": {
            "group:engineering": ["alice@example.com"],
            "group:admins": ["admin@example.com"],
            "group:ops": ["ops@example.com"],  # New group
        },
        "grants": [
            {
                "src": ["autogroup:member"],
                "dst": ["autogroup:member"],
                "ip": ["*"],
            },
            {
                "src": ["group:engineering"],
                "dst": ["tag:server"],
                "ip": ["*"],
            },
            # New grant for ops
            {
                "src": ["group:ops"],
                "dst": ["tag:database"],
                "ip": ["5432"],
            },
        ],
    }
    
    server.succeed(f"echo '{json.dumps(new_policy)}' > /var/lib/railscale/policy.json")
    print("Updated policy file with new group and grant")

with subtest("Reload policy via SIGHUP (systemctl reload)"):
    # Send SIGHUP via systemctl reload
    server.succeed("systemctl reload railscale")
    time.sleep(1)  # Give it time to reload
    
    # Verify the new policy is active
    output = railscale("policy get")
    policy = json.loads(output)
    
    assert "group:ops" in policy["groups"], "New group should be present"
    assert len(policy["grants"]) == 3, f"Should have 3 grants, got {len(policy['grants'])}"
    
    print("Policy reloaded successfully via SIGHUP")
    print(f"New groups: {list(policy['groups'].keys())}")

with subtest("Verify reload logged"):
    # Check that the reload was logged
    output = server.succeed("journalctl -u railscale --no-pager -n 50")
    assert "reload" in output.lower() or "policy" in output.lower(), \
        "Reload should be logged"
    print("Reload logged in journal")

# =============================================================================
# PHASE 4: CLI Policy Reload
# =============================================================================
with subtest("Update policy file again"):
    # Add another grant
    new_policy = {
        "groups": {
            "group:engineering": ["alice@example.com"],
            "group:admins": ["admin@example.com"],
            "group:ops": ["ops@example.com"],
            "group:security": ["security@example.com"],  # Another new group
        },
        "grants": [
            {
                "src": ["autogroup:member"],
                "dst": ["autogroup:member"],
                "ip": ["*"],
            },
            {
                "src": ["group:engineering"],
                "dst": ["tag:server"],
                "ip": ["*"],
            },
            {
                "src": ["group:ops"],
                "dst": ["tag:database"],
                "ip": ["5432"],
            },
            # New grant for security
            {
                "src": ["group:security"],
                "dst": ["*"],
                "ip": ["22"],
            },
        ],
    }
    
    server.succeed(f"echo '{json.dumps(new_policy)}' > /var/lib/railscale/policy.json")
    print("Updated policy file with security group")

with subtest("Reload policy via CLI"):
    output = railscale("policy reload")
    assert "reload" in output.lower() or "success" in output.lower(), \
        f"Reload should succeed, got: {output}"
    print(f"CLI reload output: {output}")
    
    # Verify the new policy
    output = railscale("policy get")
    policy = json.loads(output)
    
    assert "group:security" in policy["groups"], "Security group should be present"
    assert len(policy["grants"]) == 4, f"Should have 4 grants, got {len(policy['grants'])}"
    
    print("Policy reloaded successfully via CLI")

# =============================================================================
# PHASE 5: CLI Policy Set
# =============================================================================
with subtest("Set policy via CLI"):
    # Create a completely new policy
    set_policy = {
        "groups": {
            "group:developers": ["dev@example.com"],
        },
        "grants": [
            {
                "src": ["autogroup:member"],
                "dst": ["autogroup:member"],
                "ip": ["*"],
            },
            {
                "src": ["group:developers"],
                "dst": ["tag:dev-server"],
                "ip": ["*"],
            },
        ],
    }
    
    # Write to a temp file and set via CLI
    server.succeed(f"echo '{json.dumps(set_policy)}' > /tmp/new-policy.json")
    output = railscale("policy set /tmp/new-policy.json")
    assert "success" in output.lower() or "updated" in output.lower() or "2 grants" in output.lower(), \
        f"Set should succeed, got: {output}"
    print(f"CLI set output: {output}")
    
    # Verify the policy was set
    output = railscale("policy get")
    policy = json.loads(output)
    
    assert "group:developers" in policy["groups"], "Developers group should be present"
    assert "group:engineering" not in policy["groups"], "Old groups should be gone"
    assert len(policy["grants"]) == 2, f"Should have 2 grants, got {len(policy['grants'])}"
    
    print("Policy set successfully via CLI")

# =============================================================================
# PHASE 6: Restore Original Policy
# =============================================================================
with subtest("Restore original policy"):
    # Restore the original policy for any subsequent tests
    original_policy = {
        "groups": {
            "group:engineering": ["alice@example.com"],
            "group:admins": ["admin@example.com"],
        },
        "grants": [
            {
                "src": ["autogroup:member"],
                "dst": ["autogroup:member"],
                "ip": ["*"],
            },
            {
                "src": ["group:engineering"],
                "dst": ["tag:server"],
                "ip": ["*"],
            },
        ],
    }
    
    server.succeed(f"echo '{json.dumps(original_policy)}' > /var/lib/railscale/policy.json")
    railscale("policy reload")
    
    output = railscale("policy get")
    policy = json.loads(output)
    
    assert len(policy["grants"]) == 2, "Should have 2 grants after restore"
    print("Original policy restored")

print("\n" + "=" * 70)
print("POLICY RELOAD TESTS PASSED!")
print("=" * 70)
