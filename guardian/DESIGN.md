# Guardian: system design

A single Windows service that filters DNS on one laptop, enforces that the
filter can't be bypassed, and is configured remotely. Free, router
independent, no hardware.

## Goals and non-goals

- Block chosen services (Instagram, TikTok, Snapchat) plus an optional
  bedtime cut-off, on this one laptop.
- Survive a curious kid: changing DNS, browser secure-DNS, VPN apps.
- Be remotely configurable by Lovell and mom without touching the laptop.
- Non-goals: other devices, mobile data, defeating someone with admin rights
  or physical access (BIOS password and disk encryption cover that).

## Trust boundary (the most important decision)

| Account | Rights |
|---|---|
| Brother | Standard user. Cannot stop the service, edit its files, change firewall or adapter DNS. |
| Mom / Lovell | Admin. Password not known to the brother. |

Every layer below is only as strong as this boundary. If he has admin, he
can uninstall everything.

## Architecture

```
 Apps / browsers
       |  DNS (53)
       v
 127.0.0.1:53  ----------------------------+
 +------------------ guardian.exe (SYSTEM service) --------------+
 |  dnsproxy   -> blocklist match -> NXDOMAIN (blocked)          |
 |             -> else forward over DoH to an IP literal ------> internet (443)
 |  config     <- polls private GitHub file (ETag, every 5 min)  |
 |  enforcer   -> adapter DNS, firewall rules, browser policies  |
 |  events     -> local rotating log, event log, and status file  |
 +---------------------------------------------------------------+
```

## Packages

```
cmd/guardian/          entry point, wiring, (later) service install/run
internal/config/       schema, validation, atomic hot-swap Store
internal/blocklist/    suffix matcher, service presets, DoH provider list
internal/dnsproxy/     UDP+TCP DNS server, DoH forwarder, bedtime logic
internal/enforcer/     (phase 3) DNS + firewall + browser policy
internal/remote/       (phase 4) config poller
internal/events/       (phase 5) bounded local event and status reporting
```

## Key decisions

1. **DoH upstream by IP literal** (`https://1.1.1.1/dns-query`). The filter
   can't resolve names through itself, so no bootstrap problem. Config
   validation rejects hostnames.
2. **Suffix matching.** Blocking `instagram.com` also blocks
   `www.instagram.com`, `i.instagram.com`, etc. Allowlist wins over blocklist.
3. **NXDOMAIN for blocked names.** Simple and works for every record type.
4. **Fail closed.** If all upstreams fail, return SERVFAIL. No internet is
   better than unfiltered internet; the watchdog and alerts handle recovery.
5. **Browser DoH neutralised three ways:** block well-known DoH hostnames in
   the filter, answer NXDOMAIN for `use-application-dns.net` (Firefox's
   canary domain, which makes Firefox disable DoH), and set browser policies.
6. **Privacy:** log blocked hits only, not every query. All reporting is local;
  Guardian sends no outbound notifications.
7. **Hot reload.** Config lives behind an atomic pointer; a bad remote config
   is rejected and the last good one stays active.

## Enforcement plan (phase 3)

- Set IPv4 DNS to `127.0.0.1` and IPv6 DNS to `::1` on all adapters (and
  listen on both, or Windows will happily use an IPv6 resolver).
- Windows Firewall: block outbound TCP/UDP 53 and TCP 853 to non-loopback.
  The service uses 443, so it is unaffected.
- Block 443 to known public DoH resolver IPs. The service's own upstream IP
  would be caught by this, so either exclude it from the list, or scope the
  block rules to the brother's user SID so the SYSTEM service is exempt
  (verify on the real machine). Later, use WFP permit filters instead.
- Block common VPN ports (WireGuard 51820, OpenVPN 1194, IKE 500/4500).
- Registry policies (HKLM): Chrome and Edge `DnsOverHttpsMode = "off"`;
  Firefox `policies.json` with DNSOverHTTPS disabled and locked.
- Reconcile loop every ~10 s: re-apply anything that drifted and record a
  local event describing it. Binary under `C:\Program Files\Guardian` with
  admin-only ACLs.

## Remote config (phase 4)

Private GitHub repo with `config.json`. The service polls the raw file with a
read-only fine-grained token (stored in a SYSTEM-only ACL'd file) and uses
ETag to avoid needless downloads. Optional hardening: sign the config.

## Config schema

See `config.example.json`. Fields: `listen_addr`, `upstream_doh`,
`blocked_services`, `blocked_domains`, `allowed_domains`,
`block_doh_providers`, `bedtime {start,end}`, `timezone`.

## Build phases

1. DNS proxy + blocklist + bedtime, run from a console (this drop).
2. Windows service: install/uninstall, auto-restart on failure.
3. Enforcer: DNS, firewall, browser policies, reconcile loop.
4. Remote config polling.
5. Local events, status reporting, and tamper detection; no outbound alerts.
6. Hardening: WFP, ACLs, signed config, installer script.

## Known risks

- Hardcoded-IP apps and VPN clients over 443 can't be caught by DNS alone;
  the VPN port blocks and the standard-account rule cover most cases.
- Service crash with DNS pointed at 127.0.0.1 means no internet. Recovery
  action plus the watchdog should restart it within seconds.
- Test every bypass from the brother's account before handing over.
