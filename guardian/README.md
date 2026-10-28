# Guardian

Guardian is a small Go DNS filtering proxy intended for one Windows computer. It listens on a loopback address, blocks configured domains and selected service domains, optionally blocks all non-allowlisted names during a daily bedtime window, and forwards other DNS queries to upstream resolvers over DNS-over-HTTPS (DoH).

> **Current scope:** This repository contains the DNS proxy and Windows service wrapper. It does not yet configure network-adapter DNS, Windows Firewall, browser policies, VPN restrictions, remote configuration, or tamper alerts. Installing the service alone does **not** make it impossible to bypass DNS filtering. See [Security limits](#security-limits).

## How it works

1. A client sends a DNS query to Guardian's configured loopback address. The proxy serves both UDP and TCP DNS.
2. Guardian checks the question name against suffix-based block and allow rules. For example, a rule for `example.com` also matches `www.example.com`; `notexample.com` does not match it. Allow rules take precedence over block rules.
3. If a name is blocked, Guardian returns `NXDOMAIN`. If it is allowed, the proxy forwards the original DNS request to the configured DoH upstream IP-literal URLs.
4. If every upstream fails, Guardian returns `SERVFAIL` rather than an unfiltered answer. Requests to upstreams are made directly, without using HTTP proxy environment settings.
5. If bedtime is enabled, queries not on the allowlist are blocked during the configured local-time window. The start minute is included and the end minute is excluded; overnight windows such as 22:00–06:00 are supported.

The `block_doh_providers` option adds known DoH provider hostnames (including Firefox's `use-application-dns.net` canary) to the block rules. This only blocks those DNS names; it does not block direct-IP DoH clients or other unknown resolvers.

## Requirements

- Go 1.22 or later to build from source.
- Windows for service installation. On other operating systems, the console runner is available for development; install/uninstall commands are Windows-only.
- Administrator access to install or uninstall the Windows service and to change system DNS settings.

## Configure

Start with [`config.example.json`](config.example.json) and save a copy as `config.json`. The example listens on `127.0.0.1:5353`, which is convenient for local testing. For normal Windows DNS use, set `listen_addr` to `127.0.0.1:53` and configure the adapter to use that address (adapter setup is manual and not performed by this project).

```json
{
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
  "timezone": "Africa/Johannesburg"
}
```

Configuration fields:

| Field | Meaning |
|---|---|
| `listen_addr` | Loopback IP and port for the UDP and TCP DNS listeners. Use `127.0.0.1:53` for standard Windows DNS clients. |
| `upstream_doh` | One or more HTTPS DoH URLs. Each URL must use an IP-literal host (not a hostname), for example `https://1.1.1.1/dns-query`. Guardian races configured upstreams and uses the first successful response, within a shared short deadline. |
| `blocked_services` | Presets currently available: `instagram`, `tiktok`, and `snapchat`. |
| `blocked_domains` | Additional domains to block, including their subdomains. |
| `allowed_domains` | Domains exempt from block rules and bedtime blocking, including their subdomains. Allow rules win if a name also matches a block rule. |
| `block_doh_providers` | Adds the built-in list of well-known DoH hostnames to the block rules. |
| `bedtime` | Optional daily `start` and `end` values in 24-hour `HH:MM` format. Omit the field or set it to `null` to disable bedtime. Start and end must differ. |
| `timezone` | IANA time-zone name used to evaluate bedtime, such as `Africa/Johannesburg` or `America/New_York`. |

Unknown JSON fields, invalid domain rules, non-loopback listen addresses, hostnames in DoH upstream URLs, and invalid bedtime settings are rejected. Guardian loads configuration at startup; editing a file does not hot-reload the running process or service. Restart it after changing the configuration. The service installer keeps an already-existing installed config instead of replacing it with the supplied file.

## Run from source

From this directory, build and run the console version:

```sh
go build -o guardian ./cmd/guardian
go run ./cmd/guardian run -config config.json
```

The process stays in the foreground until stopped. On Windows, use an elevated terminal if binding port 53 requires it on that system. For local testing with the example's port 5353, query it with a DNS client that supports a custom port, for example:

```sh
dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 instagram.com
```

The first query should be forwarded; a blocked name should return `NXDOMAIN`. To test bedtime, temporarily configure a window that includes the current time and query a non-allowlisted name.

## Install as a Windows service

Build a Windows executable on Windows or with a Go toolchain configured for Windows, then open an **Administrator** PowerShell or Command Prompt in this directory. Example PowerShell commands:

```powershell
go build -o guardian.exe ./cmd/guardian
.\guardian.exe install -config .\config.json
```

The installer validates the supplied config, copies the executable under `%ProgramFiles%\Guardian`, and copies the config to `%ProgramData%\Guardian\config.json` if that destination does not already exist. It registers and starts the `GuardianDNS` automatic service and configures Windows service recovery actions. The data directory is restricted to SYSTEM and Administrators by the installer. The service log is written to `%ProgramData%\Guardian\guardian.log` when it can be opened.

The installer does **not** change adapter DNS or firewall rules. After installation, the machine will only use Guardian if DNS clients are configured to query its listen address. On Windows, configure the active adapter's DNS server as `127.0.0.1` using an administrator account. If using a nonstandard port such as 5353, Windows system DNS settings generally cannot specify that port; use port 53 for system-wide DNS.

To stop and remove the service, run as Administrator:

```powershell
.\guardian.exe uninstall
```

Uninstall leaves the installed executable and ProgramData files in place. Restore the adapter DNS setting to its prior value (or automatic) if Guardian is no longer running, or name resolution may stop working. To change the service configuration, edit `%ProgramData%\Guardian\config.json` with administrator rights and restart the service using Windows Services or an elevated `sc.exe` command. The service will not reread configuration until restarted.

## Security limits

Guardian filters DNS requests that reach it; DNS filtering alone is not device-wide enforcement. This version does not force adapters to use Guardian, block external DNS or DNS-over-TLS, disable browser DoH through managed policies, block VPNs, or stop applications that connect directly to IP addresses. A user who can change system settings, install software, or use an alternate network path may bypass it. A standard Windows account may have fewer options, but the protections described in the design document are not all implemented here.

For meaningful resistance to bypass, an administrator must separately configure and test adapter DNS, firewall policy, browser policies, and account permissions on the actual Windows machine. Do not rely on this project to defeat someone with administrator access or physical control of the computer. Also consider the availability impact: if DNS is directed to Guardian and the service is stopped or its upstreams are unreachable, DNS queries will fail by design.

## Development and tests

Run the project checks from this directory:

```sh
go vet ./...
go test -race ./...
```

The project includes tests for config validation and bedtime boundaries, suffix matching and allowlist precedence, and proxy behavior using a local TLS DoH test server.

## Project layout

- `cmd/guardian` — command-line entry point and Windows service lifecycle.
- `internal/config` — configuration parsing, validation, bedtime logic, and atomic config store.
- `internal/blocklist` — suffix matcher and built-in service/DoH-host rules.
- `internal/dnsproxy` — UDP/TCP DNS server and DoH forwarding.
- [`DESIGN.md`](DESIGN.md) — design goals, planned enforcement layers, and known risks.
