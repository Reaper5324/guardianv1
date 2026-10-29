# Guardian system design

Guardian is a local DNS-filtering service for one Windows laptop. Its security
boundary is a standard child account; administrator and physical access are
trusted and cannot be defeated by this project.

## What runs

```text
Applications
   | DNS UDP/TCP
   v
127.0.0.1:53 and [::1]:53
   | block/allow suffix matching, bedtime, bounded response cache
   +-- blocked --> NXDOMAIN
   +-- allowed --> HTTPS DoH to configured IP-literal upstream
                      | failure --> SERVFAIL

Guardian service (LocalSystem)
   +-- ten-second enforcement reconciliation
   +-- five-minute private GitHub config poll (optional)
   +-- bounded local events, rotating file, Windows Event Log, status JSON
   +-- loopback operations dashboard on 127.0.0.1:8765
   +-- service recovery actions and one-minute scheduled repair watchdog
```

## Decisions and invariants

1. **No resolver bootstrap cycle.** Configured DoH URLs must use IP literals.
   The remote GitHub poll uses the machine's system resolver; while the
   enforcer is active, that resolver points to Guardian, whose own DoH
   connections use IP literals.
2. **Fail closed.** A blocked name gets NXDOMAIN. If all upstreams fail, the
   proxy returns SERVFAIL and never forwards to a system/default resolver.
3. **Allowlist precedence.** Explicit allow entries win over block entries
   and bedtime. All rules match a domain and its subdomains on label
   boundaries.
4. **Last-known-good config.** Parsing, preset validation, and derived
   matcher construction happen before remote state is committed. A failed
   persistence callback does not publish an update. Boot falls back to the
   most recent valid config file. Lower remote versions are rejected.
5. **DNS cache safety.** The filter checks block and bedtime rules before
   cache lookup. Cache keys include the config snapshot namespace, entries
   have bounded capacity and TTL, SERVFAIL is never cached, and reload clears
   the cache.
6. **Local-only reporting.** Guardian sends no email, SMS, webhook, or chat
   notifications. Events are bounded, deduplicated in time windows, and
   emitted asynchronously away from the DNS request path. Status stores
   counts and event summaries, not domains or every DNS query.
7. **OS changes are repeatable.** Adapter, firewall, browser policy, service,
   and watchdog operations are designed to reconcile or restore idempotently.
   Original DNS and browser policy state are saved before changing them.

## Windows enforcement

- Active network adapters are reconciled to IPv4 `127.0.0.1` and IPv6 `::1`.
  The adapter inventory includes inactive adapters so uninstall can restore
  their saved values.
- Firewall rules use the `Guardian-` prefix. They block outbound TCP/UDP 53
  and TCP 853 outside loopback, selected resolver IPs on TCP/UDP 443, and
  common WireGuard, OpenVPN, IKE/IPsec, PPTP, and L2TP ports.
- The configured DoH upstream IPs are excluded from resolver blocks so
  LocalSystem can reach them. This is a practical implementation choice, not
  a per-user firewall exemption: an application in the standard account may
  also reach those IPs directly.
- Chrome and Edge receive managed DoH-off registry values. Firefox receives
  a locked `DNSOverHTTPS` policy in each standard Program Files installation
  found. Existing registry values and Firefox policy files are backed up
  before Guardian modifies them and restored on uninstall.
- VPN-over-443 and DoH-over-443 to unlisted IPs cannot be fully prevented.
  Portable browsers, hardcoded-IP apps, and alternate tunnels may bypass DNS
  filtering. Mobile data that does not traverse the laptop is outside scope.
- The service DACL grants full service access only to SYSTEM and
  Administrators; administrators are trusted and outside the protection
  boundary. If a prior Guardian DACL prevents an elevated administrator from
  opening the service for upgrade, the installer uses Windows service-object
  security APIs and the ownership privilege to restore that DACL. Files under
  Program Files and ProgramData are ACL-restricted by installation.
  `guardian status` checks common writable-user ACL entries; a real Windows
  standard-account test is still required to establish actual protection.
- A scheduled task runs `guardian repair` as SYSTEM every minute. That command
  starts a stopped service and reconciles enforcement. Service Control
  Manager recovery actions separately restart process failures.

All policy decisions live in platform-independent interfaces and are tested
with fakes on non-Windows systems. The PowerShell/SCM effects themselves need
validation on the supported Windows release; cross-compilation cannot verify
firewall address parsing, DNS cmdlets, ACL inheritance, or Task Scheduler
permissions.

## Remote configuration

The optional poller reads a private repository's Contents API endpoint with a
read-only token from `%ProgramData%\Guardian\github-token.txt`. It sends and
retains ETags in memory, validates strict JSON, enforces an increasing
version, builds the next matcher, persists both primary and last-known-good
files, then publishes the new DNS snapshot. Any failure leaves the active
snapshot untouched and emits a deduplicated local event. Tokens never enter
configuration, event text, or logs.

When signature enforcement is enabled, the poller verifies a detached
base64-encoded Ed25519 signature from a sibling `.sig` repository file against
the public key in ProgramData. The signing private key belongs on a trusted
administrator/developer machine, not on the child's laptop.

## Event and status data

- Event records are queued non-blockingly in a bounded channel, deduplicated
  by type/category/message within a configured window, and written to a
  rotating JSON-lines file and (on Windows) the Guardian Event Log source.
- The atomic status JSON contains service start time, config revision, remote
  sync result, last drift, upstream health, the latest 100 events, and
  category hit counts per day. It does not contain queried domain names.
- Log rotation keeps the active log and one rotated file, each capped at
  5 MiB. Individual records larger than the cap are rejected rather than
  allowed to grow the file without bound.

## Local operations dashboard

The Windows service hosts a loopback-only dashboard at
`http://127.0.0.1:8765`. It presents listener health, adapter DNS, Guardian
firewall-rule count, active configuration settings, bedtime state, upstream
health, remote sync, blocked counts, and sanitized recent events. It does not
display configured domains or per-query history. The repair action invokes
the same enforcement reconciler used by the service; reconciliations are
serialized so an operator action cannot race the periodic loop.

Configuration editing is intentionally excluded from the UI. Only an
administrator can change the protected local config; remote updates use the
existing validated and optionally signed workflow. New installs prompt for a
parent password and store only a salted PBKDF2-HMAC-SHA256 verifier in the
ACL-protected ProgramData directory. The dashboard verifies that password
before asking the SYSTEM service to stop and remove itself, restore saved DNS,
and remove its enforcement policies. Password failures are rate-limited.
The direct CLI uninstall route also requires the parent password and
administrator access. If the password is lost, an administrator must reset
the verifier before installing again.

The dashboard's POST routes require a same-origin request and bind only to
IPv4 loopback. `guardian ui` remains a standalone read-only dashboard for
development and does not receive service management callbacks.

## Operations and known failure modes

The installer accepts only a port-53 config, protects ProgramData and Program
Files, installs an automatic LocalSystem service, configures recovery, starts
the service, applies enforcement, and installs the watchdog. Reinstalling
upgrades the executable while preserving the installed configuration. Clean
uninstall restores saved adapter DNS and browser policy state and removes
Guardian firewall rules and the watchdog.

If enforcement or the service fails, DNS can fail closed and temporarily
interrupt name resolution. Use `guardian repair` from an elevated remote
session. If the service executable is unavailable, restore DHCP DNS with
`Set-DnsClientServerAddress -ResetServerAddresses`, or restore the original
static resolver values from `adapter-dns.json`; see the root README emergency
procedure. Do not remove the saved adapter-state file before restoration.

## Human verification required

Before relying on Guardian, test it from a standard account on the target
machine: adapter DNS changes, external DNS/DoT, browser Secure DNS, portable
browsers, common VPN ports, service stop/termination, config/file writes,
reboot recovery, new USB/VPN adapters, and manual DNS recovery. VPN/DoH over
443, mobile data, hardcoded IP destinations, administrator access, and physical
access remain explicit limitations even if those tests pass.
