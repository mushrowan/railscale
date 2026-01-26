# ssh policy tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# =============================================================================
# SSH Policy Tests
# =============================================================================
# Policy configured in nodes.nix:
#   ssh = [{
#     action = "accept";
#     src = [ "autogroup:member" ];
#     dst = [ "autogroup:self" ];  # Same user's devices
#     users = [ "autogroup:nonroot" ];  # Any user except root
#   }]
#
# Test cases:
#   1. user1client1 -> user1client2 as testuser: SUCCESS (same user, non-root)
#   2. user1client1 -> user2client as testuser: BLOCKED (different users)
#   3. user1client1 -> user1client2 as root: BLOCKED (root not allowed)

with subtest("SSH - Setup users and clients"):
    # Create two users for SSH testing
    railscale("users create sshuser1@example.com")
    railscale("users create sshuser2@example.com")
    
    users = railscale_json("users list")
    sshuser1 = next(u for u in users if u["email"] == "sshuser1@example.com")
    sshuser2 = next(u for u in users if u["email"] == "sshuser2@example.com")
    sshuser1_id = sshuser1["id"]
    sshuser2_id = sshuser2["id"]
    print(f"SSH User 1 ID: {sshuser1_id}, SSH User 2 ID: {sshuser2_id}")

with subtest("SSH - Connect clients with SSH enabled"):
    # Create keys for both users
    output1a = railscale(f"preauthkeys create -u {sshuser1_id} --expiration-days 1")
    sshuser1_key1 = extract_key(output1a)
    
    output1b = railscale(f"preauthkeys create -u {sshuser1_id} --expiration-days 1")
    sshuser1_key2 = extract_key(output1b)
    
    output2 = railscale(f"preauthkeys create -u {sshuser2_id} --expiration-days 1")
    sshuser2_key = extract_key(output2)
    
    # Reset and connect clients with SSH enabled
    reset_client(client1)
    reset_client(client2)
    
    # Connect user1's first client (client1)
    connect_client_with_ssh(client1, sshuser1_key1, "ssh-user1-client1")
    
    # Connect user1's second client (client2) - same user, different device
    connect_client_with_ssh(client2, sshuser1_key2, "ssh-user1-client2")
    
    user1_client1_ip = get_client_ip(client1)
    user1_client2_ip = get_client_ip(client2)
    
    assert user1_client1_ip is not None, "User1 client1 should be connected"
    assert user1_client2_ip is not None, "User1 client2 should be connected"
    print(f"User1 Client1 IP: {user1_client1_ip}, User1 Client2 IP: {user1_client2_ip}")

with subtest("SSH - Same user can SSH to own device as non-root"):
    # user1client1 -> user1client2 as testuser should SUCCEED
    # (autogroup:self allows same-user devices, autogroup:nonroot allows testuser)
    assert_ssh_works(client1, user1_client2_ip, "testuser",
                     "(same user, non-root user)")
    print("SSH from user1-client1 to user1-client2 as testuser: SUCCESS (as expected)")

with subtest("SSH - Same user cannot SSH as root"):
    # user1client1 -> user1client2 as root should be BLOCKED
    # (autogroup:nonroot excludes root)
    assert_ssh_blocked(client1, user1_client2_ip, "root",
                       "(root blocked by autogroup:nonroot)")
    print("SSH from user1-client1 to user1-client2 as root: BLOCKED (as expected)")

with subtest("SSH - Different user cannot SSH to other user's device"):
    # Now reconnect client2 as sshuser2 (different user)
    reset_client(client2)
    connect_client_with_ssh(client2, sshuser2_key, "ssh-user2-client")
    
    user2_client_ip = get_client_ip(client2)
    assert user2_client_ip is not None, "User2 client should be connected"
    print(f"User2 Client IP: {user2_client_ip}")
    
    # user1client1 -> user2client as testuser should be BLOCKED
    # (autogroup:self only allows same-user devices)
    assert_ssh_blocked(client1, user2_client_ip, "testuser",
                       "(different users, blocked by autogroup:self)")
    print("SSH from user1-client1 to user2-client as testuser: BLOCKED (as expected)")
