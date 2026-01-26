# REST API tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Note: json is imported in helpers.py

# =============================================================================
# REST API Tests
# =============================================================================

with subtest("REST API - Create API key for testing"):
    # create an admin user and api key for rest api testing
    railscale("users create admin@example.com --display-name 'API Admin'")
    users = railscale_json("users list")
    admin_user = next(u for u in users if u["email"] == "admin@example.com")
    admin_id = admin_user["id"]
    
    api_key = create_api_key_for_user(admin_id)
    assert api_key.startswith("rsapi_"), f"API key should start with rsapi_: {api_key}"
    print(f"Created API key for testing: {api_key[:20]}...")

with subtest("REST API - Unauthenticated requests are rejected"):
    status = api_request_status("/api/v1/user", "GET")
    assert status == 401, f"Unauthenticated request should return 401, got {status}"
    print("Unauthenticated request correctly rejected with 401")

with subtest("REST API - List users"):
    result = api_get("/api/v1/user", api_key)
    assert "users" in result, f"Response should contain 'users': {result}"
    users = result["users"]
    assert len(users) > 0, "Should have at least one user"
    print(f"Listed {len(users)} users via REST API")

with subtest("REST API - Create user"):
    result = api_post("/api/v1/user", api_key, {"name": "restuser"})
    assert "user" in result, f"Response should contain 'user': {result}"
    assert result["user"]["name"] == "restuser"
    rest_user_id = result["user"]["id"]
    print(f"Created user via REST API: id={rest_user_id}")

with subtest("REST API - Rename user"):
    result = api_post(f"/api/v1/user/{rest_user_id}/rename/renameduser", api_key)
    assert "user" in result, f"Response should contain 'user': {result}"
    assert result["user"]["name"] == "renameduser"
    print("Renamed user via REST API")

with subtest("REST API - Delete user"):
    result = api_delete(f"/api/v1/user/{rest_user_id}", api_key)
    # Empty response is OK for delete
    print("Deleted user via REST API")

with subtest("REST API - List nodes"):
    result = api_get("/api/v1/node", api_key)
    assert "nodes" in result, f"Response should contain 'nodes': {result}"
    nodes = result["nodes"]
    print(f"Listed {len(nodes)} nodes via REST API")

with subtest("REST API - Get node"):
    result = api_get("/api/v1/node", api_key)
    if result["nodes"]:
        node_id = result["nodes"][0]["id"]
        node_result = api_get(f"/api/v1/node/{node_id}", api_key)
        assert "node" in node_result, f"Response should contain 'node': {node_result}"
        print(f"Got node {node_id} via REST API")

with subtest("REST API - List preauth keys"):
    result = api_get("/api/v1/preauthkey", api_key)
    assert "preAuthKeys" in result, f"Response should contain 'preAuthKeys': {result}"
    print(f"Listed {len(result['preAuthKeys'])} preauth keys via REST API")

with subtest("REST API - Create preauth key"):
    result = api_post("/api/v1/preauthkey", api_key, {
        "user": int(admin_id),
        "reusable": False,
        "ephemeral": False,
        "aclTags": []
    })
    assert "preAuthKey" in result, f"Response should contain 'preAuthKey': {result}"
    new_pak_id = result["preAuthKey"]["id"]
    print(f"Created preauth key via REST API: id={new_pak_id}")

with subtest("REST API - Expire preauth key"):
    result = api_post("/api/v1/preauthkey/expire", api_key, {"id": int(new_pak_id)})
    # Empty response is OK for expire
    print("Expired preauth key via REST API")

with subtest("REST API - List API keys"):
    result = api_get("/api/v1/apikey", api_key)
    assert "apiKeys" in result, f"Response should contain 'apiKeys': {result}"
    print(f"Listed {len(result['apiKeys'])} API keys via REST API")

with subtest("REST API - Create API key"):
    result = api_post("/api/v1/apikey", api_key, {"user": int(admin_id)})
    assert "apiKey" in result, f"Response should contain 'apiKey': {result}"
    assert "key" in result, f"Response should contain 'key': {result}"
    new_api_key = result["apiKey"]
    new_api_key_prefix = result["key"]["prefix"]
    assert new_api_key.startswith("rsapi_"), "New API key should start with rsapi_"
    print(f"Created API key via REST API: {new_api_key_prefix}")

with subtest("REST API - Delete API key"):
    result = api_delete(f"/api/v1/apikey/{new_api_key_prefix}", api_key)
    # Empty response is OK for delete
    print("Deleted API key via REST API")

with subtest("REST API - Get policy"):
    result = api_get("/api/v1/policy", api_key)
    assert "policy" in result, f"Response should contain 'policy': {result}"
    policy_json = result["policy"]
    assert "grants" in policy_json, "Policy should contain grants"
    print("Got policy via REST API")

with subtest("REST API - Set policy"):
    # Save original policy first (returned as JSON string)
    original_policy_result = api_get("/api/v1/policy", api_key)
    original_policy_str = original_policy_result["policy"]
    
    # Test setting a new policy
    new_policy = {
        "groups": {"group:test": ["test@example.com"]},
        "grants": [
            {"src": ["*"], "dst": ["*"], "ip": ["*"]}
        ]
    }
    result = api_put("/api/v1/policy", api_key, {"policy": json.dumps(new_policy)})
    assert "policy" in result, f"Response should contain 'policy': {result}"
    print("Set policy via REST API")
    
    # Restore original policy (needed for SSH tests that run after)
    api_put("/api/v1/policy", api_key, {"policy": original_policy_str})
    print("Restored original policy")

with subtest("REST API - Rate limit headers present"):
    # Make a request and check headers
    cmd = f"curl -s -D - -o /dev/null -H 'Authorization: Bearer {api_key}' '{SERVER_URL}/api/v1/user'"
    headers = server.succeed(cmd)
    # tower_governor adds x-ratelimit headers when use_headers() is called
    # Check that at least one rate limit header is present
    has_ratelimit = "x-ratelimit" in headers.lower() or "ratelimit" in headers.lower()
    print(f"Rate limit headers present: {has_ratelimit}")
    print(f"Headers: {headers[:500]}...")

with subtest("REST API - Rate limiting blocks excessive requests"):
    # Make rapid requests until we hit the rate limit (429)
    # With 200 req/min (300ms replenish) and burst 33, we should hit 429
    # after ~40-50 requests since VM latency (~50ms) < replenish time
    got_rate_limited = False
    request_count = 0
    max_requests = 100  # Should be enough to exhaust burst + some replenish
    
    for i in range(max_requests):
        status = api_request_status("/api/v1/user", "GET", api_key)
        request_count += 1
        if status == 429:
            got_rate_limited = True
            print(f"Rate limited after {request_count} requests (429 Too Many Requests)")
            break
        elif status != 200:
            print(f"Unexpected status {status} on request {request_count}")
    
    assert got_rate_limited, f"Should have been rate limited within {max_requests} requests"
    print("Rate limiting is working correctly")
