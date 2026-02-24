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

  # render declarative policy to a nix store path
  policyJsonFile =
    if cfg.policy != null then pkgs.writeText "policy.json" (builtins.toJSON cfg.policy) else null;

  # resolved policy file path: declarative policy takes precedence
  resolvedPolicyFile = if policyJsonFile != null then policyJsonFile else cfg.policyFile;

  # Get the API port: from listen_port if listen_host is set, otherwise main server port
  apiPort =
    if (cfg.settings.api.listen_host or null) != null then
      cfg.settings.api.listen_port or 9090
    else
      cfg.port;

  # Parse port from "host:port" address string, with fallback
  parsePort =
    addr: fallback:
    let
      parts = lib.splitString ":" addr;
      lastPart = lib.last parts;
      parsed = lib.toIntBase10 lastPart;
    in
    if builtins.length parts >= 2 then parsed else fallback;

  # DERP port from listen_addr or advertise_port
  derpPort =
    if cfg.settings.derp.embedded_derp.advertise_port != null then
      cfg.settings.derp.embedded_derp.advertise_port
    else
      parsePort cfg.settings.derp.embedded_derp.listen_addr 3340;

  # STUN port from stun_listen_addr
  stunPort =
    if cfg.settings.derp.embedded_derp.stun_listen_addr != null then
      parsePort cfg.settings.derp.embedded_derp.stun_listen_addr 3478
    else
      3478;
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

        For a nix-managed immutable policy, use {option}`policy` instead.
        For a mutable policy editable at runtime, use {option}`policyFile`
        with a path under `/var/lib/railscale/`.
      '';
    };

    policy = lib.mkOption {
      type = lib.types.nullOr (lib.types.attrsOf lib.types.anything);
      default = null;
      example = lib.literalExpression ''
        {
          grants = [
            { src = ["autogroup:member"]; dst = ["autogroup:member"]; ip = ["*"]; }
          ];
        }
      '';
      description = ''
        Declarative grants-based policy as a Nix attribute set.
        Rendered to the Nix store and passed as an immutable policy file.
        `railscale policy set` will update the in-memory policy but changes
        will not persist across restarts.

        Mutually exclusive with {option}`policyFile`.
        For a runtime-mutable policy, use {option}`policyFile` instead.
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

    configFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = configFile;
      defaultText = lib.literalExpression ''(pkgs.formats.toml { }).generate "config.toml" cfg.settings'';
      description = ''
        path to the generated config file in the nix store.
        useful for debugging or referencing from other modules.
      '';
    };

    settings = lib.mkOption {
      description = ''
        configuration settings for railscale.
        converted to config.toml format.
        see config.example.toml in the repo
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

          ip_allocation = lib.mkOption {
            type = lib.types.enum [
              "sequential"
              "random"
            ];
            default = "sequential";
            description = ''
              ip allocation strategy for new nodes.
              sequential: allocate ips in order (100.64.0.1, 100.64.0.2, ...).
              random: allocate ips randomly within the prefix.
            '';
          };

          ephemeral_node_inactivity_timeout_secs = lib.mkOption {
            type = lib.types.ints.unsigned;
            default = 120;
            description = ''
              inactivity timeout for ephemeral nodes (in seconds).
              ephemeral nodes that disconnect and remain inactive for this
              duration will be automatically deleted.
              set to 0 to disable automatic deletion.
            '';
          };

          database = {
            db_type = lib.mkOption {
              type = lib.types.enum [
                "sqlite"
                "postgres"
              ];
              default = "sqlite";
              description = ''
                Database type. Supported: sqlite, postgres.
                For postgres, set connection_string to a postgres:// URL.
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

            sqlite = {
              write_ahead_log = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  Enable SQLite write-ahead logging (WAL) mode.
                  WAL improves concurrency by allowing simultaneous readers
                  and a single writer. Recommended for production use.
                '';
              };
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

            extra_records = lib.mkOption {
              type = lib.types.listOf (
                lib.types.submodule {
                  options = {
                    name = lib.mkOption {
                      type = lib.types.str;
                      example = "grafana.railscale.net";
                      description = "dns record name (FQDN)";
                    };
                    record_type = lib.mkOption {
                      type = lib.types.enum [
                        "A"
                        "AAAA"
                      ];
                      example = "A";
                      description = "dns record type";
                    };
                    value = lib.mkOption {
                      type = lib.types.str;
                      example = "100.64.0.5";
                      description = "dns record value (IP address)";
                    };
                  };
                }
              );
              default = [ ];
              example = [
                {
                  name = "grafana.railscale.net";
                  record_type = "A";
                  value = "100.64.0.5";
                }
              ];
              description = "extra dns records served by MagicDNS";
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
                    description = "node expiry in seconds after authentication";
                  };

                  use_expiry_from_token = lib.mkOption {
                    type = lib.types.bool;
                    default = false;
                    description = "use token expiry instead of expiry_secs";
                  };

                  group_prefix = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    example = "oidc-";
                    description = ''
                      prefix to apply to OIDC groups when mapping to policy groups.
                      e.g. with prefix "oidc-", group "engineering" becomes "oidc-engineering"
                    '';
                  };

                  extra_params = lib.mkOption {
                    type = lib.types.attrsOf lib.types.str;
                    default = { };
                    example = {
                      domain_hint = "example.com";
                    };
                    description = "custom query parameters to send with the authorize endpoint request";
                  };

                  rate_limit_per_minute = lib.mkOption {
                    type = lib.types.int;
                    default = 30;
                    description = "rate limit for OIDC endpoints (requests per minute per IP)";
                  };

                  pkce = {
                    enabled = lib.mkOption {
                      type = lib.types.bool;
                      default = true;
                      description = "enable PKCE (Proof Key for Code Exchange) for additional security";
                    };

                    method = lib.mkOption {
                      type = lib.types.enum [
                        "S256"
                        "Plain"
                      ];
                      default = "S256";
                      description = "PKCE challenge method (S256 recommended)";
                    };
                  };
                };
              }
            );
            default = null;
            description = ''
              OIDC authentication configuration.
              when set, users authenticate via your identity provider.
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
                description = "STUN server address for NAT traversal";
              };

              max_connections = lib.mkOption {
                type = lib.types.int;
                default = 1000;
                description = "maximum concurrent DERP connections";
              };

              idle_timeout_secs = lib.mkOption {
                type = lib.types.int;
                default = 300;
                description = "idle connection timeout in seconds (0 to disable)";
              };

              bytes_per_second = lib.mkOption {
                type = lib.types.int;
                default = 102400;
                description = "message rate limit in bytes/sec (client-enforced via ServerInfo)";
              };

              bytes_burst = lib.mkOption {
                type = lib.types.int;
                default = 204800;
                description = "message burst size in bytes";
              };

              connection_rate_per_minute = lib.mkOption {
                type = lib.types.int;
                default = 10;
                description = "connection rate limit per IP (connections per minute)";
              };

              stun_rate_per_minute = lib.mkOption {
                type = lib.types.int;
                default = 60;
                description = "STUN rate limit per IP (requests per minute)";
              };

              server_side_rate_limit = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  enable server-side message rate limiting.
                  protects against malicious clients that ignore ServerInfo limits.
                '';
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

            rate_limit_enabled = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "enable per-IP rate limiting for API requests";
            };

            rate_limit_per_minute = lib.mkOption {
              type = lib.types.int;
              default = 100;
              description = "maximum requests per minute per IP address";
            };

            behind_proxy = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                whether the server is behind a reverse proxy.
                when true, client IPs are extracted from X-Forwarded-For headers
                but only from requests originating from trusted_proxies.
              '';
            };

            trusted_proxies = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [
                "127.0.0.1"
                "10.0.0.0/8"
                "::1"
              ];
              description = "list of trusted proxy IP addresses or CIDR ranges";
            };
          };

          verify = {
            rate_limit_per_minute = lib.mkOption {
              type = lib.types.int;
              default = 60;
              description = ''
                Rate limit for /verify endpoint (requests per minute per IP).
                Set to 0 to disable rate limiting.
                The /verify endpoint is used by DERP servers to verify clients.
              '';
            };

            allowed_ips = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [
                "10.0.0.0/8"
                "192.168.1.100"
              ];
              description = ''
                IP allowlist for the /verify endpoint.
                When non-empty, only requests from these IPs/CIDRs are allowed.
                Leave empty to allow all IPs (rely on rate limiting only).
              '';
            };

            trusted_proxies = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [
                "127.0.0.1"
                "10.0.0.0/8"
              ];
              description = ''
                trusted proxy addresses for X-Forwarded-For extraction on /verify.
                only used when allowed_ips is non-empty.
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

          geoip_database_path = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            example = "/var/lib/railscale/GeoLite2-Country.mmdb";
            description = ''
              path to MaxMind GeoLite2-Country database for ip:country posture checks.
              enables geolocation-based access control in grants when set.
            '';
          };

          log_level = lib.mkOption {
            type = lib.types.enum [
              "trace"
              "debug"
              "info"
              "warn"
              "error"
            ];
            default = "info";
            description = "log level for tracing output";
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.policy != null && cfg.policyFile != null);
        message = "services.railscale.policy and services.railscale.policyFile are mutually exclusive";
      }
      {
        assertion = cfg.settings.dns.magic_dns -> cfg.settings.base_domain != "";
        message = "services.railscale.settings.base_domain must be set when magic_dns is enabled";
      }
      {
        assertion = cfg.settings.api.behind_proxy -> cfg.settings.api.trusted_proxies != [ ];
        message = "services.railscale.settings.api.trusted_proxies must not be empty when behind_proxy is true";
      }
      {
        assertion = cfg.settings.oidc != null -> cfg.settings.oidc.issuer or "" != "";
        message = "services.railscale.settings.oidc.issuer must be set when oidc is configured";
      }
      {
        assertion = cfg.settings.oidc != null -> cfg.settings.oidc.client_id or "" != "";
        message = "services.railscale.settings.oidc.client_id must be set when oidc is configured";
      }
    ];

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
          ${lib.optionalString (resolvedPolicyFile != null) "--policy-file ${resolvedPolicyFile}"}
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
          PrivateMounts = true;
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
        allowedTCPPorts = [ derpPort ];
        allowedUDPPorts = lib.optional (cfg.settings.derp.embedded_derp.stun_listen_addr != null) stunPort;
      })
      # API port when settings.api.openFirewall and settings.api.enabled are both true
      (lib.mkIf (cfg.settings.api.openFirewall && cfg.settings.api.enabled) {
        allowedTCPPorts = [ apiPort ];
      })
    ];
  };

  meta.maintainers = [ ];
}
