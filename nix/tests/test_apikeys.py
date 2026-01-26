# API key management CLI tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Requires: alice_id from test_users.py

# =============================================================================
# PHASE 3.5: API Key Management CLI Tests
# =============================================================================
with subtest("Create API key via CLI"):
    output = railscale(f"apikeys create -u {alice_id} --name 'My Test API Key' --expiration-days 30")
    assert "Created API key" in output
    assert "Key:" in output
    assert "rsapi_" in output
    print(f"Created API key output: {output}")

with subtest("List API keys"):
    output = railscale("apikeys list")
    assert "My Test API Key" in output or "My Test AP..." in output
    print(f"API keys list:\n{output}")

with subtest("List API keys JSON output"):
    keys = railscale_json("apikeys list")
    assert len(keys) >= 1
    assert any("rsapi_" in k["prefix"] for k in keys)
    print(f"API keys JSON: {keys}")

with subtest("Create API key with no expiration"):
    output = railscale(f"apikeys create -u {alice_id} --name 'Permanent Key' --expiration-days 0")
    assert "never" in output.lower()
    print("Created API key with no expiration")

with subtest("Expire API key"):
    keys = railscale_json("apikeys list")
    key_id = keys[0]["id"]
    output = railscale(f"apikeys expire {key_id}")
    assert "Expired" in output
    print(f"Expired API key {key_id}")

with subtest("Delete API key"):
    keys = railscale_json("apikeys list")
    key_to_delete = keys[-1] if len(keys) > 1 else keys[0]
    key_id = key_to_delete["id"]
    output = railscale(f"apikeys delete {key_id}")
    assert "Deleted" in output
    print(f"Deleted API key {key_id}")

with subtest("Filter API keys by user"):
    output = railscale(f"apikeys list -u {alice_id}")
    print(f"API keys for user {alice_id}:\n{output}")
