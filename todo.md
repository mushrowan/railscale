- [ ] (v2, later) wildcard certs per node — \*.node.base_domain in CertDomains,
      requires MagicDNS wildcard resolution support first. do not start until
      basic cert flow is solid
- [x] unvendor the snow crate — custom CryptoResolver with BE nonces instead of patching upstream
