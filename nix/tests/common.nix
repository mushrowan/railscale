# Shared test configuration for railscale NixOS VM tests
#
# Provides common client/server configuration to avoid duplication
# across test files and ensure consistent behavior.
{
  pkgs,
  railscale,
}:
let
  railscaleModule = import ../module.nix;

  # Common tailscale client flags
  commonClientFlags = [ "--verbose=5" ];

  # Common client environment to prevent contacting Tailscale infrastructure
  # TS_NO_LOGS_NO_SUPPORT: Disables telemetry
  # TS_PANIC_IF_HIT_MAIN_CONTROL: Panics if client tries to contact controlplane.tailscale.com
  commonClientEnv = {
    TS_NO_LOGS_NO_SUPPORT = "1";
    TS_PANIC_IF_HIT_MAIN_CONTROL = "1";
  };
in
{
  inherit railscaleModule commonClientFlags commonClientEnv;

  # Base client configuration - can be extended per-test
  # Usage: client1 = common.mkClient { extraPackages = [ pkgs.python3 ]; };
  mkClient =
    {
      extraPackages ? [ ],
    }:
    {
      config,
      pkgs,
      ...
    }:
    {
      services.tailscale = {
        enable = true;
        extraDaemonFlags = commonClientFlags;
      };

      systemd.services.tailscaled.environment = commonClientEnv;

      environment.systemPackages = [ pkgs.tailscale ] ++ extraPackages;

      # many tailscale up/logout cycles exhaust small VM defaults
      boot.kernel.sysctl = {
        "net.netfilter.nf_conntrack_max" = 16384;
        "net.ipv4.tcp_max_orphans" = 4096;
      };

      # enable openssh for tailscale ssh tests
      services.openssh = {
        enable = true;
        settings = {
          PermitRootLogin = "no";
          PasswordAuthentication = false;
        };
      };

      # test user for ssh tests (non-root, as per autogroup:nonroot policy)
      users.users.testuser = {
        isNormalUser = true;
        home = "/home/testuser";
        # empty password for testing - ssh key auth will be used via tailscale ssh
        initialPassword = "";
      };
    };

  # Base server settings for embedded DERP
  # Server IP is 192.168.1.3 in NixOS VM tests by default (third node after driver)
  embeddedDerpSettings = {
    derp.embedded_derp = {
      enabled = true;
      advertise_host = "192.168.1.3";
      advertise_port = 3340;
    };
  };

  # Common server firewall rules for DERP
  serverFirewall = {
    allowedTCPPorts = [
      8080
      3340
    ]; # HTTP + DERP
    allowedUDPPorts = [ 3478 ]; # STUN
  };
}
