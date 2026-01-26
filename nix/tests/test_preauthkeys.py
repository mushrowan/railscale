# Preauth key management CLI tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Requires: alice_id from test_users.py

# =============================================================================
# PHASE 3: Preauth Key Management CLI Tests
# =============================================================================
with subtest("Create preauth key via CLI"):
    output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    assert "Created preauth key" in output
    assert "Key:" in output
    print(f"Created preauth key output: {output}")

with subtest("List preauth keys"):
    output = railscale("preauthkeys list")
    assert str(alice_id) in output
    print(f"Preauth keys list:\n{output}")

with subtest("Create reusable preauth key"):
    output = railscale(f"preauthkeys create -u {alice_id} --reusable --expiration-days 1")
    assert "Reusable:  true" in output

with subtest("Create preauth key with tags"):
    output = railscale(f"preauthkeys create -u {alice_id} --tags server,web --expiration-days 1")
    assert "tag:server" in output or "server" in output

with subtest("Expire preauth key"):
    keys = railscale_json("preauthkeys list")
    key_id = keys[0]["id"]
    output = railscale(f"preauthkeys expire {key_id}")
    assert "Expired" in output

with subtest("Delete preauth key"):
    keys = railscale_json("preauthkeys list")
    key_to_delete = next(k for k in keys if not k.get("reusable", False))
    key_id = key_to_delete["id"]
    output = railscale(f"preauthkeys delete {key_id}")
    assert "Deleted" in output
