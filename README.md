# dnscomplex

`dnscomplex` is a Debian 13 one-arm split-gateway installer for RouterOS 7 upstream networks. It builds a policy-routed gateway VM that keeps RouterOS as the main LAN gateway, then selectively diverts client traffic through the VM for DNS filtering, AI/CN domain-based split routing, IPsec, SOCKS egress, and operational monitoring.

## What It Does

- Installs and manages `sing-box`, `SmartDNS`, `AdGuard Home`, `strongSwan`, `nftables`, and the dnscomplex web/metrics services.
- Supports IPv4 and IPv6 default traffic, with AI/CN profiles forced to IPv4 over IPsec.
- Uses `sing-geosite` AI rule sets and curated CN video sources for policy splitting.
- Keeps `SmartDNS` as the single DNS cache authority while `AdGuard Home` handles ad filtering, query logging, and statistics.
- Exposes a management web UI and Prometheus-style metrics endpoint.
- Generates RouterOS 7 policy-routing and Netwatch templates for fail-open deployment.

## Current Scope

- Supported OS: `Debian 13`
- Upstream router: `RouterOS 7`
- Deployment modes:
  - `routeros-policy`: recommended one-arm mode for a VM behind RouterOS
  - `vlan-gateway`: transit/LAN VLAN mode
- Included example config: `examples/routeros-policy.config.env`

## Repository Layout

- `install.sh`: main installer and runtime renderer
- `tests/install_contract_test.sh`: dry-run contract test
- `examples/routeros-policy.config.env`: non-interactive example config

## Quick Start

1. Review and copy the example config.
2. Replace all placeholder secrets such as `AI_IPSEC_USERNAME`, `AI_IPSEC_PASSWORD`, `CN_IPSEC_USERNAME`, and `CN_IPSEC_PASSWORD`.
3. Run a dry-run first:

```bash
bash install.sh --dry-run --config examples/routeros-policy.config.env
```

4. Run the real install on the Debian 13 VM:

```bash
sudo bash install.sh --yes --config /etc/dnscomplex/config.env
```

## Runtime Management

The installer writes `/usr/local/sbin/dnscomplex`. Common commands:

```bash
dnscomplex status
dnscomplex doctor
dnscomplex health --json
dnscomplex test
dnscomplex trace-domain chatgpt.com
dnscomplex refresh-nftsets
dnscomplex routeros-print
dnscomplex metrics-sample
dnscomplex soak --duration 30m --clients 1000 --dns-qps 50 --profiles ai,cn,default
```

Default service endpoints:

- Web UI: `http://<vm-ip>:8088`
- Metrics and RouterOS health probe: `http://<vm-ip>:9108/metrics`
- Health probe JSON: `http://<vm-ip>:9108/healthz`
- SOCKS: `<vm-ip>:1080`

## Open Source Notes

- This repo intentionally ignores `output/` because it contains local test artifacts and captures.
- Do not publish real IPsec credentials, private LAN details, or production backups.
- Review generated RouterOS commands before applying them.

## License

This project is licensed under the Apache License 2.0. See `LICENSE`.
