# Helper functions for railscale NixOS VM tests
#
# This file is imported by test scripts via:
#   exec(open("${./helpers.py}").read())
#
# Available globals from NixOS test framework:
#   - server, client1, client2: Machine objects
#   - subtest(name): Context manager for subtests
#   - start_all(): Start all machines

# ruff: noqa: F821
# pyright: reportUndefinedVariable=false
# pylint: disable=undefined-variable

import json
import time

SERVER_URL = "http://192.168.1.3:8080"


def railscale(cmd):
    """Run a railscale CLI command on the server"""
    return server.succeed(f"railscale {cmd}")


def railscale_json(cmd):
    """Run a railscale CLI command and parse JSON output"""
    output = server.succeed(f"railscale {cmd} -o json")
    return json.loads(output)


def extract_key(output):
    """Extract the key from CLI output (preauth or API key)"""
    for line in output.split('\n'):
        if "Key:" in line:
            return line.split("Key:")[1].strip()
    raise Exception(f"Could not find Key in output: {output}")


def connect_client(client, key, hostname, expect_success=True):
    """Connect a tailscale client with the given preauth key"""
    client.execute(
        f"timeout 15 tailscale up --login-server={SERVER_URL} "
        f"--authkey={key} --hostname={hostname} 2>&1 || true"
    )
    time.sleep(2)  # Give it time to connect
    if expect_success:
        # Wait a bit more for registration to complete
        time.sleep(3)


def get_client_ip(client):
    """Get the tailscale IP, returns None if not connected"""
    result = client.execute("tailscale ip -4 2>&1")
    if result[0] == 0 and result[1].strip().startswith("100."):
        return result[1].strip()
    return None


def disconnect_client(client):
    """Disconnect a tailscale client"""
    client.execute("tailscale logout 2>&1 || true")
    time.sleep(2)


def reset_client(client):
    """Fully reset tailscaled state"""
    client.execute("tailscale logout 2>&1 || true")
    client.execute("systemctl stop tailscaled")
    client.execute("rm -rf /var/lib/tailscale/*")
    client.execute("systemctl start tailscaled")
    client.wait_for_unit("tailscaled.service")
    time.sleep(1)


def wait_for_server():
    """Wait for the railscale server to be ready"""
    server.wait_for_unit("railscale.service")
    server.wait_for_open_port(8080)
    server.wait_for_open_port(3340)
    # Wait for STUN server (UDP 3478)
    # We can't use wait_for_open_port for UDP, so just give it time
    time.sleep(1)


def wait_for_network():
    """Wait for network to stabilize on all nodes"""
    server.wait_for_unit("dhcpcd.service")
    client1.wait_for_unit("dhcpcd.service")
    client2.wait_for_unit("dhcpcd.service")
    client1.wait_for_unit("tailscaled.service")
    client2.wait_for_unit("tailscaled.service")
    time.sleep(3)  # Give network time to fully stabilize


def create_user_and_get_id(email, display_name=None):
    """Create a user and return their ID"""
    if display_name:
        railscale(f"users create {email} --display-name '{display_name}'")
    else:
        railscale(f"users create {email}")
    users = railscale_json("users list")
    user = next(u for u in users if u["email"] == email)
    return user["id"]


def create_preauth_key(user_id, **kwargs):
    """Create a preauth key and return the key string"""
    args = f"-u {user_id}"
    if kwargs.get("reusable"):
        args += " --reusable"
    if kwargs.get("ephemeral"):
        args += " --ephemeral"
    if kwargs.get("expiration_days"):
        args += f" --expiration-days {kwargs['expiration_days']}"
    else:
        args += " --expiration-days 1"
    if kwargs.get("tags"):
        args += f" --tags {kwargs['tags']}"
    
    output = railscale(f"preauthkeys create {args}")
    return extract_key(output)


def get_node_by_name(name):
    """Get a node by its given_name"""
    nodes = railscale_json("nodes list")
    return next((n for n in nodes if n["given_name"] == name), None)
