# NixOS module for railscale - self-hosted Tailscale control server
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.railscale;
  dataDir = "/var/lib/railscale";
  runDir = "/run/railscale";

  settingsFormat = pkgs.formats.toml { };

  # Filter out null values and NixOS-specific options from settings before generating TOML
  # - openFirewall: NixOS-specific, controls firewall module
  filterSettings =
    settings:
    lib.filterAttrsRecursive (
      n: v:
      v != null && n != "openFirewall" && !(lib.isList v && v == [ ]) && !(lib.isAttrs v && v == { })
    ) settings;

  configFile = settingsFormat.generate "config.toml" (filterSettings cfg.settings);

  # Get the API port: from listen_port if listen_host is set, otherwise main server port
  apiPort =
    if (cfg.settings.api.listen_host or null) != null then
      cfg.settings.api.listen_port or 9090
    else
      cfg.port;
in
{
  options.services.railscale = {
    enable = lib.mkEnableOption "railscale, self-hosted Tailscale control server";

    package = lib.mkPackageOption pkgs "railscale" { };

    user = lib.mkOption {
      type = lib.types.str;
      default = "railscale";
      description = ''
        User account under which railscale runs.

        ::: {.note}
        If left as the default value this user will automatically be created
        on system activation, otherwise you are responsible for
        ensuring the user exists before the railscale service starts.
        :::
      '';
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "railscale";
      description = ''
        Group under which railscale runs.

        ::: {.note}
        If left as the default value this group will automatically be created
        on system activation, otherwise you are responsible for
        ensuring the group exists before the railscale service starts.
        :::
      '';
    };

    address = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      example = "0.0.0.0";
      description = "Listening address of railscale.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      example = 443;
      description = "Listening port of railscale.";
    };

    policyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/etc/railscale/policy.json";
      description = ''
        Path to grants-based policy file (JSON format).
        See the railscale documentation for policy syntax.
      '';
    };

    adminSocket = {
      path = lib.mkOption {
        type = lib.types.path;
        default = "${runDir}/admin.sock";
        description = ''
          Path to the admin gRPC Unix socket.
          CLI commands use this socket to communicate with the server.
        '';
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = cfg.group;
        defaultText = lib.literalExpression "config.services.railscale.group";
        description = ''
          Group that can access the admin socket.
          Users in this group can run railscale CLI commands.
        '';
      };
    };

    settings = lib.mkOption {
      description = ''
        Configuration settings for railscale.
        These are converted to config.toml format.
        See [config.example.toml](https://github.com/anomalyco/railscale/blob/main/config.example.toml)
        for available options.
      '';
      default = { };
      type = lib.types.submodule {
        freeformType = settingsFormat.type;

        options = {
          server_url = lib.mkOption {
            type = lib.types.str;
            default = "http://127.0.0.1:8080";
            example = "https://ts.example.com";
            description = "The URL clients will use to connect to this server.";
          };

          listen_addr = lib.mkOption {
            type = lib.types.str;
            default = "${cfg.address}:${toString cfg.port}";
            defaultText = lib.literalExpression ''"''${cfg.address}:''${toString cfg.port}"'';
            description = "Address to bind the HTTP server to.";
          };

          noise_private_key_path = lib.mkOption {
            type = lib.types.path;
            default = "${dataDir}/noise_private.key";
            description = ''
              Path to the Noise protocol private key file.
              A missing key will be automatically generated on first run.
            '';
          };

          base_domain = lib.mkOption {
            type = lib.types.str;
            default = "railscale.net";
            example = "ts.example.com";
            description = ''
              Base domain for MagicDNS hostnames.
              Nodes will be accessible as <hostname>.<base_domain>.
              This must be different from the server_url domain.
            '';
          };

          prefix_v4 = lib.mkOption {
            type = lib.types.str;
            default = "100.64.0.0/10";
            description = ''
              IPv4 prefix for node address allocation.
              Must be within 100.64.0.0/10 (CGNAT range reserved for Tailscale).
            '';
          };

          prefix_v6 = lib.mkOption {
            type = lib.types.str;
            default = "fd7a:115c:a1e0::/48";
            description = ''
              IPv6 prefix for node address allocation.
              Must be within fd7a:115c:a1e0::/48 (Tailscale's ULA range).
            '';
          };

          database = {
            db_type = lib.mkOption {
              type = lib.types.enum [ "sqlite" ];
              default = "sqlite";
              description = ''
                Database type. Currently only SQLite is supported.
              '';
            };

            connection_string = lib.mkOption {
              type = lib.types.str;
              default = "${dataDir}/db.sqlite";
              description = ''
                Database connection string or file path.
                For SQLite, this is the path to the database file.
              '';
            };
          };

          dns = {
            magic_dns = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable MagicDNS for hostname resolution.";
            };

            override_local_dns = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Override local DNS settings on clients.
                When true, forces clients to use railscale's DNS config.
                When false, clients keep their local DNS settings.
              '';
            };

            nameservers = {
              global = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [
                  "1.1.1.1"
                  "8.8.8.8"
                ];
                description = ''
                  Global nameservers for DNS queries.
                  Can be IP addresses or DNS-over-HTTPS URLs.
                '';
              };

              split = lib.mkOption {
                type = lib.types.attrsOf (lib.types.listOf lib.types.str);
                default = { };
                example = {
                  "corp.example.com" = [
                    "10.0.0.53"
                    "10.0.0.54"
                  ];
                };
                description = ''
                  Split DNS: route specific domains to dedicated nameservers.
                '';
              };
            };

            search_domains = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Search domains to inject to clients.";
            };
          };

          oidc = lib.mkOption {
            type = lib.types.nullOr (
              lib.types.submodule {
                freeformType = settingsFormat.type;

                options = {
                  issuer = lib.mkOption {
                    type = lib.types.str;
                    example = "https://sso.example.com";
                    description = "OIDC issuer URL.";
                  };

                  client_id = lib.mkOption {
                    type = lib.types.str;
                    example = "railscale";
                    description = "OIDC client ID.";
                  };

                  client_secret = lib.mkOption {
                    type = lib.types.str;
                    default = "";
                    description = ''
                      OIDC client secret.
                      Consider using client_secret_path instead for better security.
                    '';
                  };

                  client_secret_path = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    example = "/run/secrets/railscale-oidc-secret";
                    description = ''
                      Path to file containing the OIDC client secret.
                      Useful for secrets management (SOPS, systemd credentials, etc.).
                      Takes precedence over client_secret if both are set.
                    '';
                  };

                  scope = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [
                      "openid"
                      "profile"
                      "email"
                    ];
                    description = "OAuth2 scopes to request.";
                  };

                  email_verified_required = lib.mkOption {
                    type = lib.types.bool;
                    default = true;
                    description = "Require email to be verified by the identity provider.";
                  };

                  allowed_domains = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [ ];
                    example = [ "example.com" ];
                    description = "Restrict access to specific email domains.";
                  };

                  allowed_users = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [ ];
                    description = "Restrict access to specific email addresses.";
                  };

                  allowed_groups = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [ ];
                    description = "Restrict access to users in specific groups.";
                  };

                  expiry_secs = lib.mkOption {
                    type = lib.types.int;
                    default = 15552000; # 180 days
                    description = "Node expiry in seconds after authentication.";
                  };
                };
              }
            );
            default = null;
            description = ''
              OIDC authentication configuration.
              When set, users authenticate via your identity provider.
            '';
          };

          derp = {
            derp_map_url = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = "https://controlplane.tailscale.com/derpmap/default";
              description = ''
                URL to fetch the public DERP map from.
                Set to null to disable fetching from URL.
              '';
            };

            derp_map_path = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "Path to a local DERP map file (JSON format).";
            };

            update_frequency_secs = lib.mkOption {
              type = lib.types.int;
              default = 3600;
              description = "How often to refresh the DERP map (in seconds).";
            };

            embedded_derp = {
              enabled = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  Enable the embedded DERP relay server.
                  When enabled, your railscale server also acts as a relay.
                '';
              };

              region_id = lib.mkOption {
                type = lib.types.int;
                default = 999;
                description = "Region ID for the embedded DERP server.";
              };

              region_name = lib.mkOption {
                type = lib.types.str;
                default = "railscale";
                description = "Human-readable name shown in Tailscale UI.";
              };

              listen_addr = lib.mkOption {
                type = lib.types.str;
                default = "0.0.0.0:3340";
                description = "Address to bind the DERP HTTPS listener to.";
              };

              advertise_host = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = ''
                  Hostname or IP advertised to clients.
                  Defaults to the host from server_url if not set.
                '';
              };

              advertise_port = lib.mkOption {
                type = lib.types.nullOr lib.types.port;
                default = null;
                description = ''
                  Port advertised to clients.
                  Defaults to the port from listen_addr if not set.
                '';
              };

              cert_path = lib.mkOption {
                type = lib.types.path;
                default = "${dataDir}/derp_cert.pem";
                description = "Path to TLS certificate (PEM format).";
              };

              tls_key_path = lib.mkOption {
                type = lib.types.path;
                default = "${dataDir}/derp_tls_key.pem";
                description = "Path to TLS private key (PEM format).";
              };

              private_key_path = lib.mkOption {
                type = lib.types.path;
                default = "${dataDir}/derp_private.key";
                description = "Path to DERP protocol private key.";
              };

              stun_listen_addr = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = "0.0.0.0:3478";
                description = "STUN server address for NAT traversal.";
              };
            };
          };

          tuning = {
            node_store_batch_size = lib.mkOption {
              type = lib.types.int;
              default = 100;
              description = "NodeStore batch size for write operations.";
            };

            node_store_batch_timeout_ms = lib.mkOption {
              type = lib.types.int;
              default = 500;
              description = "NodeStore batch timeout in milliseconds.";
            };

            register_cache_expiration_secs = lib.mkOption {
              type = lib.types.int;
              default = 900;
              description = "Registration cache expiration in seconds.";
            };

            register_cache_cleanup_secs = lib.mkOption {
              type = lib.types.int;
              default = 1200;
              description = "Registration cache cleanup interval in seconds.";
            };

            map_keepalive_interval_secs = lib.mkOption {
              type = lib.types.int;
              default = 60;
              description = "Interval between keep-alive messages for map connections.";
            };
          };

          api = {
            enabled = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable the REST API.
                When false, /api/v1/* endpoints return 404.
              '';
            };

            listen_host = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "127.0.0.1";
              description = ''
                Host/IP to bind the API listener to.
                If null (default), API runs on the main server port.
                If set, API runs on a separate listener at listen_host:listen_port.
              '';
            };

            listen_port = lib.mkOption {
              type = lib.types.port;
              default = 9090;
              description = ''
                Port for the API listener. Only used when listen_host is set.
              '';
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Whether to open the firewall for the REST API port.
                Only takes effect when {option}`settings.api.enabled` is also true.

                If {option}`settings.api.listen_host` is set, opens {option}`settings.api.listen_port`.
                Otherwise, opens the main server port ({option}`port`).
              '';
            };
          };

          taildrop_enabled = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Enable Taildrop file sharing between nodes.";
          };

          randomize_client_port = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Randomize WireGuard port on clients.";
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # Merge listen_addr from address:port
    services.railscale.settings.listen_addr = lib.mkDefault "${cfg.address}:${toString cfg.port}";

    # Create user and group
    users.groups.${cfg.group} = lib.mkIf (cfg.group == "railscale") { };

    users.users.${cfg.user} = lib.mkIf (cfg.user == "railscale") {
      description = "Railscale service user";
      home = dataDir;
      group = cfg.group;
      isSystemUser = true;
    };

    # Systemd service
    systemd.services.railscale = {
      description = "Railscale - Self-hosted Tailscale control server";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      script = ''
        exec ${lib.getExe cfg.package} serve \
          --config ${configFile} \
          --admin-socket ${cfg.adminSocket.path} \
          ${lib.optionalString (cfg.policyFile != null) "--policy-file ${cfg.policyFile}"}
      '';

      serviceConfig =
        let
          capabilityBoundingSet = [ "CAP_CHOWN" ] ++ lib.optional (cfg.port < 1024) "CAP_NET_BIND_SERVICE";
        in
        {
          User = cfg.user;
          Group = cfg.group;
          Restart = "always";
          RestartSec = "5s";
          Type = "simple";

          # Enable policy hot-reload via: systemctl reload railscale
          ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";

          # State and runtime directories
          StateDirectory = "railscale";
          StateDirectoryMode = "0750";
          RuntimeDirectory = "railscale";
          RuntimeDirectoryMode = "0750";

          # Security hardening
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectHostname = true;
          ProtectClock = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          RemoveIPC = true;
          UMask = "0077";
          NoNewPrivileges = true;
          LockPersonality = true;
          RestrictRealtime = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "@chown"
          ];
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";

          # Capabilities for binding to low ports
          CapabilityBoundingSet = capabilityBoundingSet;
          AmbientCapabilities = capabilityBoundingSet;
        };
    };

    # Add CLI to system packages for administration
    environment.systemPackages = [ cfg.package ];

    # Set default socket path for CLI commands
    environment.variables.RAILSCALE_ADMIN_SOCKET = cfg.adminSocket.path;

    # Open firewall ports
    networking.firewall = lib.mkMerge [
      # DERP/STUN ports when embedded DERP is enabled
      (lib.mkIf cfg.settings.derp.embedded_derp.enabled {
        allowedTCPPorts = [
          (
            if cfg.settings.derp.embedded_derp.advertise_port != null then
              cfg.settings.derp.embedded_derp.advertise_port
            else
              3340
          )
        ];
        allowedUDPPorts = lib.optional (cfg.settings.derp.embedded_derp.stun_listen_addr != null) 3478;
      })
      # API port when settings.api.openFirewall and settings.api.enabled are both true
      (lib.mkIf (cfg.settings.api.openFirewall && cfg.settings.api.enabled) {
        allowedTCPPorts = [ apiPort ];
      })
    ];
  };

  meta.maintainers = [ ];
}
