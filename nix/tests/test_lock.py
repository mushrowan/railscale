# Tailnet Lock (TKA) tests
#
# Tests the lock CLI commands:
# - railscale lock status (when disabled)
# - railscale lock init (initialise TKA)
# - railscale lock status (when enabled)
# - railscale lock sign (sign a node)
# - railscale lock disable (disable TKA with secret)

# ruff: noqa: F821
# pyright: reportUndefinedVariable=false
# pylint: disable=undefined-variable

print("\n" + "=" * 70)
print("TAILNET LOCK (TKA) TESTS")
print("=" * 70)

# ==========================================================================
# Test: lock status when disabled
# ==========================================================================
with subtest("lock status shows disabled"):
    output = railscale("lock status")
    assert "disabled" in output.lower(), f"Expected disabled status, got: {output}"
    print("lock status shows disabled when not initialised")

# ==========================================================================
# Test: lock init
# ==========================================================================
with subtest("lock init initialises TKA"):
    # Run with --force to skip confirmation prompt
    output = railscale("lock init --force --disablement-secrets 2")
    assert "initialised" in output.lower() or "success" in output.lower(), \
        f"Expected success message, got: {output}"
    
    # Extract private key from output
    private_key = None
    for line in output.split('\n'):
        if "nlpriv:" in line:
            # Extract the key (format: "  nlpriv:hexhexhex")
            parts = line.strip().split()
            for part in parts:
                if part.startswith("nlpriv:"):
                    private_key = part
                    break
            if private_key:
                break
    
    assert private_key is not None, f"Could not find private key in output: {output}"
    print(f"TKA initialised, got private key: {private_key[:20]}...")
    
    # Extract disablement secrets
    disablement_secrets = []
    in_secrets_section = False
    for line in output.split('\n'):
        if "disablement secret" in line.lower():
            in_secrets_section = True
            continue
        if in_secrets_section and ":" in line:
            # Format is "  1: hexhexhex"
            parts = line.strip().split(":")
            if len(parts) >= 2:
                secret = parts[1].strip()
                if len(secret) == 64:  # 32 bytes = 64 hex chars
                    disablement_secrets.append(secret)
    
    assert len(disablement_secrets) == 2, \
        f"Expected 2 disablement secrets, got {len(disablement_secrets)}: {output}"
    print(f"Got {len(disablement_secrets)} disablement secrets")

# ==========================================================================
# Test: lock status when enabled
# ==========================================================================
with subtest("lock status shows enabled"):
    output = railscale("lock status")
    assert "enabled" in output.lower(), f"Expected enabled status, got: {output}"
    assert "head:" in output.lower(), f"Expected head hash, got: {output}"
    print("lock status shows enabled after init")

# ==========================================================================
# Test: lock status JSON output
# ==========================================================================
with subtest("lock status JSON output"):
    output = railscale("lock status -o json")
    import json
    status = json.loads(output)
    assert status["enabled"] == True, f"Expected enabled=true, got: {status}"
    assert status.get("head") is not None, f"Expected head hash, got: {status}"
    assert len(status.get("keys", [])) == 1, f"Expected 1 key, got: {status}"
    print(f"JSON status correct: enabled={status['enabled']}, keys={len(status.get('keys', []))}")

# ==========================================================================
# Test: sign an existing node with lock
# ==========================================================================
with subtest("sign a node with lock"):
    # Use an existing node from the database instead of creating a new one
    # (client1/client2 have been used by other tests)
    nodes = railscale_json("nodes list")
    
    # Just pick the first node
    assert len(nodes) > 0, "Expected at least one node in the database"
    node = nodes[0]
    node_id = node["id"]
    print(f"Found node: id={node_id}, name={node.get('given_name')}")
    
    # Sign the node with our private key
    output = railscale(f"lock sign {node_id} --key {private_key}")
    assert "success" in output.lower() or "signed" in output.lower(), \
        f"Expected success message, got: {output}"
    print(f"Node {node_id} signed successfully")

# ==========================================================================
# Test: lock disable
# ==========================================================================
with subtest("lock disable with secret"):
    # Use the first disablement secret
    secret = disablement_secrets[0]
    output = railscale(f"lock disable {secret}")
    assert "disabled" in output.lower(), f"Expected disabled message, got: {output}"
    print("TKA disabled successfully")

# ==========================================================================
# Test: lock status after disable
# ==========================================================================
with subtest("lock status shows disabled after disable"):
    output = railscale("lock status")
    assert "disabled" in output.lower(), f"Expected disabled status, got: {output}"
    print("lock status shows disabled after disable")

print("\n" + "=" * 70)
print("TAILNET LOCK TESTS PASSED!")
print("=" * 70)
