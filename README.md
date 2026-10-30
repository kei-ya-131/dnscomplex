# dnscomplex

`dnscomplex` is a Debian 13 one-arm split-gateway installer for RouterOS 7 upstream networks. It builds a policy-routed gateway VM that keeps RouterOS as the main LAN gateway, then selectively diverts client traffic through the VM for DNS filtering, AI/CN domain-based split routing, IPsec, SOCKS egress, and operational monitoring.

## What It Does

- Installs and manages `sing-box`, `Xray-core`, `SmartDNS`, `AdGuard Home`, `strongSwan`, `nftables`, and the dnscomplex web/metrics services.
- Supports IPv4 and IPv6 default traffic, with AI/CN profiles forced to IPv4 over either IPsec or an Xray sidecar.
- Uses `sing-geosite` AI rule sets and curated CN video sources for policy splitting.
- Supports AI/CN egress switching between `ipsec` and `xray`; Xray URI import supports `vless://`, `vmess://`, `trojan://`, and `ss://`.
- Keeps `SmartDNS` as the single DNS cache authority while `AdGuard Home` handles ad filtering, query logging, and statistics.
- Exposes a management web UI for service state, traffic, AI/CN domains/geosite/SRS, SOCKS, IPsec, Xray egress, installation wizard, release/update channels, support bundles, and Prometheus-style metrics.
- Generates RouterOS 7 policy-routing and Netwatch templates for fail-open deployment.

## Current Scope

- Supported OS: `Debian 13`
- Upstream router: `RouterOS 7`
- Deployment modes:
  - `routeros-policy`: recommended one-arm mode for a VM behind RouterOS
  - `vlan-gateway`: transit/LAN VLAN mode
- Included example config: `examples/routeros-policy.config.env`

Latest release: **v0.3.0**. See [fixes, validation and upgrade notes](docs/releases/v0.3.0.md).

## Repository Layout

- `install.sh`: main installer and runtime renderer
- `tests/`: installer, runtime, configuration, routing and recovery regression tests
- `tools/`: bounded profile data-plane probe
- `docs/releases/`: public, deployment-independent release notes
- `examples/routeros-policy.config.env`: non-interactive example config

## Quick Start

1. Review and copy the example config.
2. Replace the example VPN server names, remote ID, LAN addresses and all placeholder secrets such as `AI_IPSEC_USERNAME`, `AI_IPSEC_PASSWORD`, `CN_IPSEC_USERNAME`, and `CN_IPSEC_PASSWORD`.
3. New users can generate a starter config with the runtime wizard after installation, or use the example file before installation:

```bash
dnscomplex wizard > config.env
dnscomplex validate-config config.env
```

4. Run a dry-run first:

```bash
bash install.sh --dry-run --config examples/routeros-policy.config.env
```

5. Run the real install on the Debian 13 VM:

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
dnscomplex set-egress ai xray
dnscomplex set-xray-uri ai '<redacted-xray-uri>'
dnscomplex test-xray ai
dnscomplex refresh-nftsets
dnscomplex routeros-print
dnscomplex metrics-sample
dnscomplex soak --duration 60 --clients 50 --dns-qps 20 --profiles ai,cn,default
dnscomplex validate-config /etc/dnscomplex/config.env
dnscomplex render-config --redacted
dnscomplex update-software --channel stable
dnscomplex update-software --channel pinned --version v1.2.3
dnscomplex support-bundle --include-logs standard
```

Default service endpoints:

- Web UI: `http://<vm-ip>:8088`
- Metrics and RouterOS health probe: `http://<vm-ip>:9108/metrics`
- Health probe JSON: `http://<vm-ip>:9108/healthz`
- SOCKS in `routeros-policy` mode: `<vm-ip>:10800` (the configured LAN address only)

AI/CN Xray mode carries TCP/UDP through local Xray SOCKS inbounds. ICMP for AI/CN nftset destinations is blocked in Xray mode instead of falling back to default routing, so `ping` may fail by design.

## Reliability and Verification

Persistent web changes now run as durable operations. The API returns an operation ID; completion is reported only after validation, application and post-checks. A disconnected browser does not cancel or resubmit the operation. Failed recovery keeps its private backup and blocks conflicting changes.

AI/CN routing remains domain-based. CN defaults cover the configured Chinese video domains, not every Chinese service. AI/CN readiness is checked separately and IPv6 bypass remains closed for those profiles; default traffic may use working IPv4 and IPv6.

Run the main regression suite from a clean checkout:

```bash
bash -n install.sh
bash tests/install_contract_test.sh
python3 tests/web_operation_lifecycle_test.py
python3 tests/web_operation_contract_test.py
python3 tests/soak_resource_limits_test.py
```

The installer contract includes runtime reliability tests. Native namespace/wire tests require Linux, privileges and the binaries/versions described in their source; they are not represented as passing on other hosts. Historical one-off deployment helpers, their version-pinned acceptance tests, private baselines and captures are not distributed; they are not part of the installer or public regression suite.

## Updates and Support Bundles

The daily update timer refreshes domain/geosite/SRS data; it does not promise unattended Debian or proxy-core upgrades. Explicit `update-software` commands are separate.

`DNSCOMPLEX_UPDATE_CHANNEL` controls explicit runtime updates:

- `stable`: use latest non-prerelease GitHub releases.
- `beta`: allow the newest non-draft GitHub release, including prereleases.
- `pinned`: update GitHub-managed binaries only to `DNSCOMPLEX_PINNED_VERSION`.

`update-software` still performs backup, package/release update, config checks, health checks, and rollback on failure. Logs are written under `/var/log/dnscomplex/update-*.log`.

`support-bundle` creates a redacted `.tar.gz` for GitHub issues. It removes IPsec passwords, Xray URIs/UUIDs, GitHub tokens, private IPv4/IPv6 addresses, `.local` hostnames, cookies, and session-like secrets before packaging.

## Open Source Notes

- This repo intentionally ignores `output/` because it contains local test artifacts and captures.
- Do not publish real IPsec credentials, private LAN details, or production backups.
- Review generated RouterOS commands before applying them.

## License

This project is licensed under the Apache License 2.0. See `LICENSE`.
