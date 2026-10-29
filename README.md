# Guardian

Guardian is a Windows DNS-filtering service for one computer. It runs as
LocalSystem, serves DNS on IPv4 and IPv6 loopback, forwards allowed queries
over HTTPS to configured IP-literal DNS-over-HTTPS (DoH) upstreams, and applies
local network and browser policies to make ordinary DNS bypass harder. Events,
logs, and status are kept locally; Guardian sends no notifications.

The service is intended to deter a curious **standard (non-administrator)
account**. It is not a way to control an administrator or someone with
physical access to the computer. Do not describe the controls as proven on a
specific Windows machine until the manual checklist below has been run there.

## What Guardian does

- Blocks configured domains and the Instagram, TikTok, and Snapchat presets
  using suffix matching. An allowlist entry wins over a block entry.
- Returns NXDOMAIN for blocked names and SERVFAIL when no DoH upstream can
  answer. It never falls back to an unfiltered resolver.
- Supports an optional local-time bedtime window. The start minute is
  included, the end minute is excluded, and overnight windows are supported.
- Listens on `127.0.0.1:53` and `[::1]:53` when configured for port 53.
- Reconciles active adapter DNS, firewall rules, and browser policies every
  ten seconds on Windows. The original DNS values are recorded so uninstall
  can restore them, including for adapters that are disconnected at uninstall
  time.
- Blocks outbound DNS on ports 53 and TCP 853 to non-loopback addresses,
  selected common VPN ports, and known public DoH resolver IPs. Configured
  DoH upstream IPs are deliberately excluded from the IP blocks so the
  SYSTEM service can reach them.
- Sets Chrome and Edge `DnsOverHttpsMode=off` policies and Firefox's managed
  `DNSOverHTTPS` policy when those browsers are installed.
- Can poll a private GitHub repository every five minutes using ETags. The
  read-only token is stored separately in the protected ProgramData folder.
  Config revisions cannot be downgraded. Optional Ed25519 verification is
  supported.
- Keeps bounded local event and status files, an event-log source on Windows,
  and a bounded DNS response cache. Status and event views are available from
  the command line.

The design choices and remaining limitations are described in
[`guardian/DESIGN.md`](guardian/DESIGN.md).

## Limits and bypasses

Guardian is a local DNS control, not a complete network firewall or parental
control suite:

- It does not filter traffic over **mobile data** that bypasses this computer.
- Applications that use hardcoded IP addresses can avoid DNS filtering.
- **VPNs or DoH over TCP/UDP 443 cannot be fully stopped.** The rules block
  listed public resolver IPs and common VPN ports, but alternate IPs,
  tunneling, and portable software may bypass them.
- Configured upstream resolver IPs are exempt from the DoH-IP block; a program
  running as the child could potentially use those IPs directly.
- Browser policies cover standard managed installations. Portable or
  nonstandard browsers may not honor them.
- An administrator can remove or modify the service, firewall rules, browser
  policies, or files. Physical access is also outside the threat model.
- If all upstreams are unreachable, filtered DNS returns SERVFAIL. This is
  fail-closed behavior and can temporarily prevent name resolution.

Do not treat the list of resolver IPs as complete or permanently current.
Review and update it when upstream or resolver choices change. VPNs over 443
are explicitly a remaining limitation.

## Configuration

Copy [`guardian/config.example.json`](guardian/config.example.json) to a
working directory and edit it. A normal system-wide configuration must use
port 53; port 5353 is useful for local development but `guardian install`
rejects it.

```json
{
  "version": 1,
  "listen_addr": "127.0.0.1:53",
  "upstream_doh": [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query"
  ],
  "blocked_services": ["instagram", "tiktok", "snapchat"],
  "blocked_domains": [],
  "allowed_domains": [],
  "block_doh_providers": true,
  "bedtime": { "start": "22:00", "end": "06:00" },
  "timezone": "Africa/Johannesburg",
  "remote": {
    "enabled": false,
    "owner": "example-owner",
    "repository": "guardian-config",
    "branch": "main",
    "path": "config.json",
    "require_signature": false
  }
}
```

`remote` is optional. When enabled, set it to the private GitHub repository
and path that contains the complete JSON configuration. Store the fine-grained,
read-only token as plain token text in
`%ProgramData%\Guardian\github-token.txt` (one line; no quotes). Never put the
token in JSON or command-line arguments. The installer applies a
SYSTEM/Administrators-only ACL to that directory. The downloaded config must
have a version greater than the active version. A failed fetch, invalid
config, or rejected signature leaves the active configuration unchanged.

When `require_signature` is true, the remote file must have a sibling
`config.json.sig` (base64 Ed25519 signature over the exact config bytes), and
`%ProgramData%\Guardian\config-public.key` must contain the base64 public key.
Keep the private signing key off the child's computer. If signatures are
enabled, provide the public key to `install.ps1`. Generate a keypair on a
trusted administrator/developer machine, retain the private file securely,
and upload only the public key:

```powershell
.\guardian.exe keygen -private .\guardian-config-private.key -public .\guardian-config-public.key
.\guardian.exe sign -config .\repo\config.json -key .\guardian-config-private.key -out .\repo\config.json.sig
```

Commit `config.json` and its `.sig` together. The signature covers the exact
file bytes; regenerate it after every edit. `keygen` and `sign` refuse to
overwrite existing output files.

The parser rejects unknown JSON fields, invalid domains, unknown service
presets, non-loopback listen addresses, and DoH URLs whose host is not an IP
literal. A validated file is backed up as `config.json.last-good.json`; a bad,
missing, or older primary file falls back to that copy at startup. Editing the
local config does not hot-reload the service; use `guardian repair` for
enforcement, and restart the service to load a local file change.

## Build and local development

From the repository root:

```powershell
Set-Location .\guardian
go test ./...
go vet ./...
go test -race ./...
go build .\cmd\guardian
```

To cross-compile the Windows executable:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go build -o .\guardian.exe .\cmd\guardian
Remove-Item Env:GOOS, Env:GOARCH
```

For console testing, use a loopback port other than 53 and a DNS client that
supports a custom port. The production installer requires port 53.

## Install and operate on Windows

Build `guardian.exe` before transferring files; `install.ps1` never builds
anything. Run this from an elevated PowerShell session with the supplied
binary and config:

```powershell
.\install.ps1 -GuardianExe .\guardian.exe -ConfigPath .\config.json `
  -TokenPath .\github-token.txt -PublicKeyPath .\config-public.key
```

Omit `-TokenPath` if remote configuration is disabled and omit
`-PublicKeyPath` if signatures are not required. The script checks elevation
and required files, prints the executable's source revision, validates the
supplied config before making system changes, protects ProgramData, provisions
supplied token/public-key files, and invokes `guardian.exe install`. The
service installer preserves an already-installed config and parent-password
verifier during upgrades; it warns when the supplied config differs instead
of silently replacing active settings. Run `guardian.exe version` to inspect
the exact source revision embedded in a build.

On a new installation, `guardian install` prompts for a parent password
without echoing it to the console. Choose at least 12 characters and retain
the password; only a salted verifier is saved in the protected
`%ProgramData%\Guardian\parent-auth.json`. The local dashboard requires this
password for its uninstall action. A standard account can request uninstall
through the dashboard; the SYSTEM service performs the operation and restores
saved DNS. The command-line `uninstall` path also verifies the password and
still requires administrator access. If the password is lost, an
administrator can reset the verifier and reinstall.

When the service is running, open
[`http://127.0.0.1:8765`](http://127.0.0.1:8765) on the device. The dashboard
shows DNS listener health, adapter DNS, firewall-rule presence, configuration
and bedtime settings, upstream and remote-sync status, blocked counts, and
recent local event summaries. It offers an enforcement repair action and a
parent-password-gated uninstall action. It intentionally does not edit
configuration; make changes through the protected administrator config
workflow or the remote signed-config workflow. The `guardian ui` command can
also serve a standalone read-only view for local development.

Double-clicking the packaged `guardian.exe` starts the local dashboard in
your browser; it does not install or activate DNS filtering. The console stays
open while the dashboard is served. To enable service enforcement, use the
elevated PowerShell installer above. The package includes a valid port-53
`config.json`, `install.ps1`, and this guide. If the dashboard cannot start,
the executable prints the error and suggested commands and waits for Enter so
the message remains visible.

Useful elevated or remote-session commands:

```powershell
& "$env:ProgramFiles\Guardian\guardian.exe" status
& "$env:ProgramFiles\Guardian\guardian.exe" events -n 50
& "$env:ProgramFiles\Guardian\guardian.exe" repair
& "$env:ProgramFiles\Guardian\guardian.exe" uninstall
```

`status` reports service state, config version, adapter DNS, Guardian firewall
rules, last remote sync, last drift, upstream health, and an ACL self-check.
`events` reads the most recent locally persisted events. The default data
folder is `%ProgramData%\Guardian`; `adapter-dns.json` contains the saved
pre-Guardian DNS configuration. Use a remote admin session (such as RDP or
SSH) to inspect these commands; Guardian does not send network alerts.

## Manual standard-account verification

Run these checks while signed in as the child's **standard account** after an
administrator has installed Guardian. Use a harmless test domain such as
`example.com` and the configured blocked domains. Do not test with a real
unauthorized account or bypass service.

| Test | Expected result |
|---|---|
| Try changing an adapter's DNS in Windows settings or an unelevated terminal. | The operation is denied or requires administrator credentials. `guardian status` continues to show `127.0.0.1` and `::1` on active adapters. |
| Query a blocked domain through normal Windows DNS. | It returns NXDOMAIN. An allowlisted subdomain still resolves. |
| Try an external resolver on UDP/TCP 53 or TCP 853. | The connection/query is blocked. |
| Open Chrome or Edge Secure DNS settings and try to enable it. | The managed policy keeps Secure DNS off; `chrome://policy` or `edge://policy` should show the policy. |
| Check Firefox's DNS-over-HTTPS setting and `about:policies`. | DNS-over-HTTPS is disabled and locked for a standard installation. |
| Install a VPN that requires elevation and test its common ports. | Standard-account installation should be denied; listed VPN ports are blocked. A VPN that tunnels over 443 may still work and is a known limitation. |
| Run a portable browser or a DoH client. | Managed browser policy may not apply. Known resolver IPs are blocked except configured upstream IPs; an alternate resolver or DoH/VPN over 443 may bypass filtering. Record any bypass as a limitation, not a pass. |
| Try stopping or deleting `GuardianDNS` from Services or an unelevated shell. | The standard account is denied. |
| Try editing `%ProgramData%\Guardian\config.json`, logs, status, token, or the installed binary. | Writes/deletion are denied. `guardian status` should report no weak ACLs. |
| End `guardian.exe` from Task Manager. | A standard account should not be able to terminate the SYSTEM service process. If the service crashes, Windows recovery and the scheduled watchdog should restart/repair it. |
| Reboot the computer. | The service starts automatically, listeners become available, and adapter DNS/enforcement is restored. |
| Connect a USB tether or another new adapter. | Within the reconcile interval, its DNS is set to Guardian. Check `guardian status`; test DNS through it. |
| Wait through an enabled bedtime window. | A non-allowlisted domain returns NXDOMAIN; allowlisted names continue to resolve. |
| Disconnect upstream internet temporarily. | Queries return SERVFAIL, never answers from an unfiltered resolver. Restore connectivity and confirm `guardian status` reports healthy upstreams. |

Use the system's normal change-management procedure for all network tests.
Do not install an untrusted VPN or execute an unknown DoH client merely to test
the filter.

## Emergency recovery

If name resolution breaks, use an administrator account or remote admin
session. First try:

```powershell
& "$env:ProgramFiles\Guardian\guardian.exe" repair
& "$env:ProgramFiles\Guardian\guardian.exe" status
```

To remove Guardian cleanly and restore saved adapter DNS:

```powershell
& "$env:ProgramFiles\Guardian\guardian.exe" uninstall
```

If the service executable is unavailable or uninstall cannot restore DNS,
inspect `%ProgramData%\Guardian\adapter-dns.json` to recover each adapter's
original IPv4/IPv6 DNS values. For adapters that previously used DHCP DNS, an
administrator can restore automatic DNS with:

```powershell
Get-NetAdapter -IncludeHidden | ForEach-Object {
  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ResetServerAddresses
  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -ResetServerAddresses
}
ipconfig /flushdns
```

`-ResetServerAddresses` restores DHCP-provided DNS; it is **not** appropriate
for an adapter that previously had static DNS. For static settings, use the
exact values saved in `adapter-dns.json` and restore them with
`Set-DnsClientServerAddress -ServerAddresses`. Do not delete the saved state
file until adapter DNS has been restored and verified.

## Validation and Windows-only verification

The repository includes tests for config validation and fallback, version
rejection, bedtime boundaries/DST, blocklist precedence, the running DNS
proxy, DoH failure, cache bounds/TTL, enforcement decisions with fakes,
remote config/signatures, event deduplication, and status persistence.
Windows firewall, adapter, browser policy, service ACL, scheduled-task ACL,
and install/uninstall behavior still require testing on the target Windows
version and hardware. Cross-compilation is not a substitute for that manual
verification.
