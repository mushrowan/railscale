# railscale

if you're reading this, it means i just pushed this because i tend to put off
publicising code and i just wanted to get it out there into the world. half of
this readme could be completely wrong as it's almost 3am and i am tired and just
typed it all up like a moron. i will come back and fix i promise

> [!CAUTION] **this has not been properly audited.** for something that is meant
> to be secure like a zero trust mesh vpn, that should scream out to you as a
> red flag. if you are serious about security, you should **NOT** use this until
> further notice.

> PLEASE PAY ATTENTION TO THE LICENCE. FOR NOW IT IS NOT "OPEN SOURCE". YOU
> CANNOT USE (YET) USE IT IN A COMMERCIAL SETTING. the reason for this is just
> an additional measure against some well-meaning fool trying to use this in a
> security-sensitive scenario. i do not want someone to start using this, get
> hacked, and leak a bunch of customer data or something. if/when this gets a
> proper security audit, i will change this to something else more permissive.
> prolly mit or gpl or whatever.

> before you try to be helpful and use your codex credits to audit, yes i have
> already done this. but this is not a substitute for a proper audit.

## a self-hosted tailscale control server written in rust

they told me i couldn't do it

## features

- **full ts2021 protocol support** - works with official tailscale clients
- **oidc authentication** - sign in with google, github, whatever
- **grants policy system** - acls but swaggier
- **device posture** - restrict access based on device attributes and
  geolocation
- **embedded derp server** - built-in relay with rate limiting
- **taildrop** - file sharing between nodes (same-user)
- **tailnet lock** - cryptographic verification of node keys
- **ephemeral nodes** - auto-cleanup of temporary devices
- **rest api** - manage users, nodes, keys
- **nixos module** - first-class nix support with comprehensive options
- **too much other stuff** - it's 2am and i cannot be bothered to remember

## quickstart

### nix

```nix
# flake.nix
{
  inputs.railscale.url = "github:mushrowan/railscale";

  outputs = { self, nixpkgs, railscale }: {
    nixosConfigurations.myserver = nixpkgs.lib.nixosSystem {
      modules = [
        railscale.nixosModules.default
        {
          services.railscale = {
            enable = true;
            settings = {
              server_url = "https://vpn.example.com";
              base_domain = "ts.example.com";

              # optional: oidc login
              oidc = {
                issuer = "https://accounts.google.com";
                client_id = "your-client-id";
                client_secret_path = "/run/secrets/oidc-secret"; # use sops-nix
              };
            };
          };
        }
      ];
    };
  };
}
```

### config file

```toml
# config.toml
server_url = "https://vpn.example.com"
listen_addr = "0.0.0.0:8080"
base_domain = "ts.example.com"

[database]
db_type = "sqlite"
connection_string = "/var/lib/railscale/db.sqlite"

[database.sqlite]
write_ahead_log = true  # recommended for production

[derp.embedded_derp]
enabled = true
region_id = 900
region_name = "my-derp"

# optional oidc
[oidc]
issuer = "https://accounts.google.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
```

### docker

not yet

## https / reverse proxy

railscale speaks plain http. for production, stick a reverse proxy in front:

**caddy** (easiest - automatic https):

```
vpn.example.com {
    reverse_proxy localhost:8080
}
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;
    ssl_certificate /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

why no built-in acme? reverse proxies are battle-tested, more flexible, and keep
railscale simple. caddy literally does automatic https with zero config.

## connecting clients

```bash
# on your tailscale client
tailscale up --login-server=https://vpn.example.com
```

## cli

```bash
# run the server
railscale serve --config /etc/railscale/config.toml

# manage users
railscale users list
railscale users create alice

# manage preauth keys
railscale preauthkeys create --user alice --reusable
railscale preauthkeys list

# manage nodes
railscale nodes list
railscale nodes delete 12345

# reload policy without restart
railscale policy reload

# tailnet lock
railscale lock init              # initialise tailnet lock
railscale lock status            # show lock status
railscale lock sign <node-key>   # sign a node key
railscale lock disable           # disable tailnet lock
```

## policy (grants)

```json
{
  "groups": {
    "group:dev": ["alice@example.com", "bob@example.com"]
  },
  "grants": [
    { "src": ["group:dev"], "dst": ["autogroup:member"], "ip": ["*"] }
  ],
  "ssh": [
    {
      "action": "accept",
      "src": ["group:dev"],
      "dst": ["tag:servers"],
      "users": ["root"]
    }
  ]
}
```

> **note on persistence**: policy updates via the REST API or CLI are held in
> memory only. they're lost on restart. for persistent policy, use a policy file
> with `--policy` or the nixos `policyFile` option. runtime updates are for
> testing/development.

## taildrop

file sharing between devices on the same tailnet. currently works for same-user
transfers (alice's laptop -> alice's phone). cross-user transfers need grants
support which isn't done yet.

```bash
# send a file
tailscale file cp ~/photo.jpg myphone:

# receive files
tailscale file get ~/Downloads/
```

enable in config:

```toml
taildrop_enabled = true
```

## tailnet lock

nodes can't join unless signed by trusted nodes - protects against compromised
control server.

```bash
# initialise lock (generates signing key)
railscale lock init

# check status
railscale lock status

# sign a node
railscale lock sign nodekey:abc123...

# disable lock (requires disablement secret from init)
railscale lock disable
```

## status

my current status is that i am in bed and i am comfy, thank you for asking

okay but actually, the status is that i'm going to continue actively working on
this. there are many things indeedy which need to be fixed, ironed out, added.

current limitations:

- ssh policy works-ish but i'll be honest i only realised that i forgot to
  properly implement it today and then madly wrote it all in like 4 hours so
  yeah it might be broken
  - doesn't yet support
    [acceptEnv](https://tailscale.com/docs/features/tailscale-ssh#acceptenv)
- app connectors - not yet
- cross-user taildrop (needs grants support for peer capabilities)
- probably like 50 million other things

cool stuff:

- nixos vm tests that make sure core functionality works
  - can i just quickly say, nixos vm tests are insane. like they are nuts.
    you're telling me i can just simulate a little cluster of servers or
    whatever and then tell them exactly what output/exit codes i expect and then
    qemu just figures it all out? that's insaneo style

## license

PolyForm Noncommercial License 1.0.0

see the top of the readme for the reason for this. tldr; i will change this in
the future but for now i do not what to be worrying about some silly person
leaking social security numbers with a piece of software i made

## see also

- [headscale](https://github.com/juanfont/headscale) - the og self-hosted
  tailscale server (go)
- [tailscale](https://tailscale.com) - the real deal
- [shellac](https://github.com/she-llac) - the cherished friend who kept telling
  me to keep going while i built this

### the name

the railscale fandom is dying. reply "i love to get railed" to affirm your love
for railscale
