# User management CLI tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# =============================================================================
# PHASE 2: User Management CLI Tests
# =============================================================================
with subtest("Create user via CLI"):
    output = railscale("users create alice@example.com --display-name 'Alice Smith'")
    assert "Created user" in output
    assert "alice" in output
    print(f"Created user output: {output}")

with subtest("List users shows created user"):
    output = railscale("users list")
    assert "alice" in output
    print(f"Users list:\n{output}")

with subtest("List users JSON output"):
    users = railscale_json("users list")
    assert len(users) == 1
    assert users[0]["email"] == "alice@example.com"
    print(f"Users JSON: {users}")

with subtest("Create second user"):
    railscale("users create bob@example.com")
    users = railscale_json("users list")
    assert len(users) == 2
    user_names = [u["email"] for u in users]
    assert "alice@example.com" in user_names
    assert "bob@example.com" in user_names

with subtest("Rename user"):
    users = railscale_json("users list")
    bob = next(u for u in users if u["email"] == "bob@example.com")
    bob_id = bob["id"]

    output = railscale(f"users rename {bob_id} robert@example.com")
    assert "Renamed" in output

    users = railscale_json("users list")
    user_emails = [u["email"] for u in users]
    assert "robert@example.com" in user_emails
    assert "bob@example.com" not in user_emails

with subtest("Delete user"):
    users = railscale_json("users list")
    robert = next(u for u in users if u["email"] == "robert@example.com")
    robert_id = robert["id"]

    output = railscale(f"users delete {robert_id}")
    assert "Deleted" in output

    users = railscale_json("users list")
    assert len(users) == 1
    assert users[0]["email"] == "alice@example.com"

# Get alice's ID for later use (exported as global)
users = railscale_json("users list")
alice_id = users[0]["id"]
print(f"Alice's ID: {alice_id}")
