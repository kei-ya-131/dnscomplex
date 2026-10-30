# VM Network Reliability Design

**Date:** 2026-07-17
**Status:** Approved
**Target:** `root@192.168.8.200`

## Problem

The VM appeared to lose Internet access and became very slow after running for
several days. The VM itself was healthy: CPU, memory, disk, conntrack, interface
errors, RouterOS gateway latency, IPv4 Internet access, IPv6 Internet access,
raw DNS, DoT, and DoH were all available.

The active outage was a SmartDNS liveness failure:

- SmartDNS remained `active` under systemd.
- UDP listeners `127.0.0.1:6053`, `:6054`, and `:6055` each had a full receive
  queue of `213120` bytes.
- Queries to all three listeners timed out.
- sing-box DNS on `127.0.0.1:1053` consequently timed out.
- AdGuard Home waited about 20 seconds for each query before returning an
  upstream timeout.
- Metrics show the first sustained zero DNS success ratio at
  `2026-07-17 08:56 CST`.

SmartDNS Release48 has a reported DoH HTTP/2 connection reuse failure mode.
The installed Release48.2 process state is consistent with a resolver
deadlock, but the exact internal trigger cannot be proven without a core dump.
The design therefore both mitigates the reported HTTP/2 path and detects the
observable deadlock independently of its trigger.

## Goals

1. Restore low-latency DNS and Internet access.
2. Detect and recover from a live-but-unresponsive SmartDNS process.
3. Preserve useful nftset routing data during resolver outages.
4. Make backups and automatic updates reliable while metrics are being
   written.
5. Repair stopped or misleading timers and noisy DHCP resolver hooks.
6. Improve health checks so they test real connectivity.
7. reproduce every persistent repair in `install.sh`, deploy the same script
   to `/root/install.sh`, and verify both copies are identical.

## Invariants

The implementation must not change these behaviours:

- Routing remains domain based. It must not force all WeChat mini-program,
  UnionPay, Chinese, or other traffic into one route.
- The existing `default`, `AI`, and `CN` classifications remain authoritative.
- Current AI and CN egress modes and IPsec policy routing remain unchanged.
- The externally used SOCKS listener remains
  `192.168.8.200:10800`; it must not become `0.0.0.0:1080`.
- WeChat domains that currently classify as `default` remain direct.
- `macbookair.local` must not receive a static address. `.local` resolution
  continues to follow mDNS or RouterOS DHCP/DNS state.
- RouterOS remains `192.168.8.253`, and the VM remains
  `192.168.8.200`.
- IPv6 remains enabled because end-to-end IPv6 connectivity was verified.
- Existing uncommitted changes in `install.sh` and
  `tests/install_contract_test.sh` must be preserved.

## Architecture

### 1. SmartDNS Upstream Mitigation

`smartdns_upstream_line` will render every existing `server-https` entry with
`-alpn http/1.1`. Existing DoH provider URLs, DoT fallback endpoints, and
resolver groups remain unchanged. This follows the upstream workaround for
the Release48 HTTP/2 reuse issue without changing routing or DNS provider
semantics.

The SmartDNS systemd service receives a managed drop-in with:

- `Restart=always`
- `RestartSec=2s`
- `TimeoutStopSec=5s`

The shorter stop timeout ensures that a stopped or deadlocked process can be
replaced promptly even when it cannot handle `SIGTERM`.

### 2. Resolver Watchdog

A dedicated `dnscomplex watchdog` command runs from
`dnscomplex-health.timer`. It performs bounded checks and avoids the current
minute-by-minute configuration rewrites.

Each run:

1. Queries representative A records through ports `6053`, `6054`, and `6055`
   with a two-second timeout.
2. If all three fail, waits two seconds and repeats the three checks.
3. If both rounds fail, queries independent positive controls directly through
   `1.1.1.1` and `223.5.5.5`.
4. Restarts SmartDNS only when at least one positive control succeeds.
5. Enforces a 600-second restart cooldown using state under
   `/run/dnscomplex`.
6. Waits up to 15 seconds for all three SmartDNS listeners to recover.
7. Starts nftset refresh only after DNS recovery.

If the direct positive controls also fail, the watchdog records an upstream
network outage and does not create a restart loop. A failed recovery returns a
non-zero status and remains visible in systemd and health output.

The watchdog still repairs genuinely inactive core services and missing policy
routes, but it does not run config migration, `systemctl enable`, sysctl
rewrites, `swanctl --load-all`, or unconditional route rewrites on every tick.

### 3. Failure-Safe nftset Refresh

Each AI and CN refresh first gathers candidate public IPv4 addresses in a
temporary file. The refresh records:

- total domains,
- domains with an A answer,
- unique public addresses,
- domains without an answer.

No nftset is flushed before successful resolution. Candidate additions are
committed in one nft transaction, while prior elements remain protected by
their existing timeout and expire naturally. A profile with zero answers:

- keeps its last-known-good elements,
- does not update its `last_refresh` timestamp,
- returns failure so systemd and health checks expose the outage.

AI and CN are handled independently. Failure of one profile does not discard
valid data from the other.

### 4. Consistent Backup and Update Locking

`dnscomplex backup` creates a temporary filesystem snapshot before creating
the archive:

- static configuration and state files are copied into a staging root;
- `metrics.sqlite3` is copied with Python's SQLite backup API;
- transient SQLite `-wal` and `-shm` files are excluded;
- the final archive is created only from the immutable staging root;
- temporary files are removed on success or failure.

A lock under `/run/lock` prevents simultaneous backup/update operations.
Archive validation lists the archive and runs SQLite
`PRAGMA integrity_check` on an extracted copy before a backup is reported as
successful. This removes the recurring `file changed as we read it` update
failure.

### 5. Network and Timer Hygiene

In `routeros-policy` mode, installation idempotently adds
`nohook resolv.conf` to `dhcpcd.conf`. `/etc/resolv.conf` remains managed by
dnscomplex, so dhcpcd no longer invokes the disabled systemd-resolved D-Bus
service for every RA or DHCP event.

The CN override timer changes to a persistent six-hour calendar schedule. All
dnscomplex timers are explicitly restarted after unit files are rendered, so
an already active `elapsed` timer cannot retain an obsolete schedule.

The plain health path performs actual bounded IPv4 and IPv6 TCP/DNS probes.
An IPv6 route lookup alone is not considered proof of connectivity.

### 6. Deployment Flow

Before changing the VM:

1. Capture current service status, listener queues, routing, nftsets, config
   hashes, and relevant journal excerpts.
2. Create a consistent pre-change backup using an out-of-band SQLite snapshot
   if the installed backup command is still broken.
3. Record invariant configuration values.

Deployment then:

1. Copies the tested local installer to `/root/install.sh`.
2. Applies the installer using the current `/etc/dnscomplex/config.env`.
3. Restarts SmartDNS to clear the existing deadlock.
4. Rebuilds AI and CN nftsets after DNS is healthy.
5. Resets the historical failed update unit only after backup verification.

## Error Handling and Rollback

- Every disruptive action is preceded by a backup.
- SmartDNS restart is scoped to SmartDNS; AdGuard, sing-box, Xray, and IPsec
  are not restarted unless their own check fails.
- Watchdog restart attempts are rate limited.
- nftset refresh never replaces usable data with an empty result.
- Installer validation runs before service restart.
- If post-deployment DNS, routing, or config invariants fail, restore the
  pre-change archive and previous installer, then restart the prior service
  set.
- Logs must not expose IPsec credentials, web passwords, Xray URIs, or other
  secrets.

## Test Strategy

### Local Regression Tests

Tests must cover:

- DoH entries render with `-alpn http/1.1`.
- All routing, SOCKS, `.local`, and egress invariants remain rendered.
- Watchdog does not restart on a single failed round.
- Watchdog restarts on two complete listener failures with a successful
  positive control.
- Watchdog does not restart when both listeners and positive controls fail.
- Watchdog cooldown prevents restart loops.
- nftset refresh preserves existing elements and timestamps on zero answers.
- Successful nftset refresh commits unique public addresses and timestamps.
- Backup uses an immutable staging root and SQLite backup.
- CN override timer has a recurring future schedule.
- routeros-policy rendering suppresses dhcpcd resolver hooks.

The implementation follows a red-green cycle for each behavioural change.
`bash -n install.sh` and the complete installer contract test must pass.

### Remote Verification

The VM is not considered repaired until all of these pass with fresh evidence:

1. SmartDNS, sing-box DNS, and AdGuard DNS answer within bounded latency.
2. Default, AI, and CN sample domains retain their expected classification and
   egress.
3. SOCKS is reachable at `192.168.8.200:10800`, including from the Xray server
   at `192.168.8.180`.
4. IPsec SAs and policy routes remain established.
5. IPv4 and IPv6 direct connectivity both work.
6. A DNS load/soak run completes without queue growth or timeout regression.
7. A controlled live-but-unresponsive SmartDNS fault is detected and recovered
   within the watchdog bound.
8. A forced nftset refresh during DNS failure retains last-known-good entries.
9. A backup taken while metrics are active passes archive and SQLite integrity
   checks.
10. CN override and health timers show a future trigger.
11. dhcpcd/systemd-resolved D-Bus noise does not recur during an observation
    window.
12. `systemctl --failed` contains no unresolved dnscomplex failure.
13. Local `install.sh` and remote `/root/install.sh` have the same SHA-256
    digest.

## Acceptance Criteria

The change is complete only when:

- the active DNS outage is cleared;
- the original domain-routing behaviour is unchanged;
- all local regression tests pass;
- all remote verification items pass or an explicitly external dependency is
  documented with evidence;
- every persistent VM modification is generated by `install.sh`;
- no secret appears in committed files or the final report.
