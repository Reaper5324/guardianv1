
INSTRUCTIONS:

You are a senior Go engineer working on "Guardian", a Windows-only parental-control service for ONE child's laptop. Read DESIGN.md, README.md and every .go file first. Then implement everything still missing, so the project is complete, tested, and installable. Work through the phases below in order, committing after each one.

CONTEXT
- Guardian runs as a SYSTEM Windows service, auto-starts, and restarts itself on failure. It runs a filtering DNS proxy on 127.0.0.1:53 (miekg/dns): blocked names return NXDOMAIN, everything else is forwarded over DoH to IP-literal upstreams, with bedtime blocking and fail-closed SERVFAIL on upstream failure.
- Threat model: a determined kid on a STANDARD (non-admin) Windows account. Only mom and the developer (who is remote) hold admin rights. We do not try to defeat admin access or physical access.
- Constraints: free only, no router changes, no paid services, minimal dependencies (stdlib, miekg/dns, golang.org/x/sys; anything else needs a written justification). No outbound notification services at all (no Telegram, email, SMS, webhooks). The developer manages it remotely over a remote session (Tailscale + RDP/SSH), so it must be configurable without touching the laptop and inspectable from the command line.
- Already done: DNS proxy, blocklist and presets, strict config validation, bedtime, Windows service install/uninstall/recovery, ProgramData ACL lockdown, tests.
- Remove every mention of Telegram from DESIGN.md and README.md and replace it with the local reporting described in Phase 5.

INVARIANTS (never break these)
1. Fail closed: if filtering cannot work, return SERVFAIL, never an unfiltered answer.
2. Allowlist beats blocklist. Blocked names return NXDOMAIN. Upstreams must be IP literals.
3. A bad config (local or remote) must never replace a good running one. Keep a last-known-good copy on disk and use it if the main config is bad at boot, so a bad file cannot cause a crash loop or leave the child with no internet.
4. Privacy: log blocked hits only, never every query. Never log secrets.
5. Every OS-touching action must be idempotent and safe to re-run.

PHASE 3: ENFORCER (internal/enforcer)
Goal: make it hard to bypass the filter from a standard account.
- Set IPv4 DNS to 127.0.0.1 and IPv6 DNS to ::1 on all active adapters, and listen on both 127.0.0.1:53 and [::1]:53 (config validation must allow the ::1 loopback). Handle adapters added later (VPN adapters, USB tethering, new Wi-Fi) by re-checking periodically. Record each adapter's original DNS so uninstall can restore it.
- Windows Firewall rules (netsh advfirewall or PowerShell, whichever is more reliable; use a distinct rule-name prefix "Guardian-" so rules can be found, replaced and removed):
  a. Block outbound TCP/UDP 53 and TCP 853 to all non-loopback addresses.
  b. Block outbound 443 (and QUIC UDP 443 where relevant) to well-known public DoH/DoT resolver IPs, with a maintained list. The service's own upstream IPs must still work: either exclude them from the list, or scope the block rules to the standard user accounts' SIDs so the SYSTEM service is exempt. Investigate which works reliably, test the choice, and document it.
  c. Block common VPN protocols and ports (WireGuard 51820, OpenVPN 1194, IKE/IPsec 500 and 4500, PPTP 1723, L2TP). Note honestly in the docs that VPNs over 443 cannot be fully stopped.
- Browser policies via HKLM registry: Chrome and Edge DnsOverHttpsMode = "off"; Firefox via policies.json (DNSOverHTTPS disabled and locked) in the Firefox install directory. Handle missing browsers gracefully. Also consider blocking browser extension installs and the Secure DNS settings page if feasible.
- Reconcile loop (every ~10 s, context-aware, no goroutine leaks): detect drift in adapter DNS, firewall rules, registry keys, and the service configuration itself, fix it, and emit a drift event to the event sink (Phase 5) describing what drifted.
- Put every OS call behind an interface (for example Netsh runner, Registry, AdapterLister) so the logic is unit-testable on Linux with fakes. Do not shell out with unvalidated strings.
- `guardian install` must apply enforcement. `guardian uninstall` must remove all Guardian-* firewall rules and registry policies and restore the original adapter DNS, so removal never leaves the laptop without internet. Add `guardian status` (service state, adapter DNS, rules present, config version, last remote sync, last drift) and `guardian repair`.

PHASE 4: REMOTE CONFIG (internal/remote)
- Poll a config file from a PRIVATE GitHub repo (raw contents API) using a read-only fine-grained token, every ~5 minutes, using ETag/If-None-Match. The token lives in a SYSTEM/Administrators-only file in ProgramData, never in the main config, never logged.
- Validate the downloaded config with the existing strict Parse, then atomically swap it in and call Reload so config and matcher change as one snapshot. On any failure (network, 401/403/404, invalid JSON, validation error) keep the current config and record an event (deduplicated, see Phase 5). Save each accepted config as the new last-known-good.
- Optional but desirable: verify an Ed25519 signature over the config (public key stored in ProgramData, a small CLI command to generate the keypair and sign), so a compromised repo cannot push a malicious config. Make it configurable and document it.
- Add a monotonically increasing "version" field to the config and refuse downgrades, to prevent replay of an old config.
- The remote fetch itself needs DNS: make sure it works while the machine's DNS points at Guardian (for example by resolving through the proxy's own upstream path), and test this.

PHASE 5: EVENTS, TAMPER DETECTION AND LOCAL REPORTING (internal/events)
No network notifications. Everything is local and inspectable by an administrator.
- Define an EventSink interface with implementations: the rotating log file, the Windows Event Log (golang.org/x/sys/windows/svc/eventlog, source "Guardian"), and an in-memory fake for tests.
- Events: service started or restarted, drift detected and repaired, remote sync failed, remote config applied (with version), upstreams unreachable for more than N minutes, config rejected (with the reason), and blocked-hit counts.
- Deduplicate and rate-limit: a flapping condition must produce at most one line per window with a repeat count, so logs cannot be spammed. The event path must be non-blocking and bounded so it can never stall DNS.
- Write a status file (atomic write, admin-only ACL) in ProgramData with: service start time, current config version, last remote sync result and time, last drift (what and when), upstream health, the last N events, and blocked-hit counts per service per day (counts only, never domain lists or per-query history).
- Add `guardian status` (human-readable) and `guardian events -n 50` that read from it, designed to be run over a remote session.

PHASE 6: HARDENING AND POLISH
- Service security descriptor so only Administrators and SYSTEM can stop or reconfigure it. Verify that a standard user cannot stop, delete or modify the service, the binary in Program Files, the config, the logs, the status file, or the scheduled tasks. Add a self-check in `guardian status` that reports any weak ACL.
- Add a second watchdog independent of the service process (for example a Scheduled Task running as SYSTEM every minute that starts the service if it is stopped and runs `guardian repair`), installed and removed by install/uninstall.
- Safe upgrade path: `guardian install` over an existing installation should stop the service, replace the binary, keep the config, and restart, with rollback on failure. Never leave a half-installed state.
- Response cache for DNS answers (respect TTL with sane min/max, never cache SERVFAIL, bounded size) to cut DoH latency. The cache must never serve a blocked name and must be cleared on config change.
- Bedtime: confirm behavior around DST, boundary minutes, and a changed system clock or time zone; add tests.
- Log rotation that cannot grow without bound; structured, consistent log lines.
- A single `install.ps1` that builds nothing and only installs a provided guardian.exe plus config and token files, with clear errors.
- Update README.md and DESIGN.md so they match reality: what is enforced, what is NOT (mobile data, hardcoded-IP apps, VPN over 443, admin or physical access), how to test every bypass from the child's account, how to inspect status remotely, and how to recover if something breaks (including a documented emergency procedure to restore normal DNS manually).

ENGINEERING RULES
- Keep the existing package structure and style. Small focused commits, one phase per commit, clear messages.
- After EVERY phase run and fix until clean: gofmt -l . (no output), go vet ./... for GOOS=linux and GOOS=windows, go test -race ./..., and cross-compile with GOOS=windows GOARCH=amd64 go build ./cmd/guardian. Never push code that does not compile. A previous round of changes shipped a compile error and a Run() that shut the server down right after starting, so verify behavior, not just compilation.
- Write table-driven unit tests for all logic: reconcile decisions with fake adapters and fake netsh, config swap and rollback, last-known-good fallback, version-downgrade refusal, signature verification, event deduplication and rate limiting, status file contents, cache TTL, bedtime edges. Add an integration-style test that starts the proxy on a free loopback port with a fake DoH server and checks that blocked, allowed, bedtime, SERVFAIL and cache all behave correctly. Tests must not need Windows or admin rights; anything Windows-specific goes behind build tags and interfaces.
- Concurrency: use context cancellation everywhere, no goroutine leaks, no data races (-race clean), no unbounded queues or maps.
- Security: validate all inputs, no shell string interpolation of config values, least privilege, secrets only in protected files. Fail safe.
- Do not weaken any invariant to make a test pass. If you find a design flaw, fix it and explain.

FINAL DELIVERABLE
When all phases are done, produce:
1. A findings and decisions summary: for each phase, what was built, what you chose and why, and any limitation you could not solve.
2. The exact manual test checklist for a human to run on the real Windows laptop from a standard account (change DNS, enable browser Secure DNS, install a VPN app, use a portable browser, stop the service, edit the config, kill the process, reboot, plug in a USB tether), each with the expected result.
3. A list of anything that could not be verified without real Windows and needs human testing.
Then run the full check suite one last time and report the results.