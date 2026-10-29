//go:build windows

package enforcer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"guardian/internal/config"
)

type CommandRunner interface {
	Run(context.Context, string, []string, []string) ([]byte, error)
}

type execCommandRunner struct{}

var setLastError = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetLastError")

func (execCommandRunner) Run(ctx context.Context, executable string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	if env != nil {
		cmd.Env = mergeEnv(os.Environ(), env)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		details := strings.TrimSpace(strings.Join([]string{
			strings.TrimSpace(stdout.String()),
			strings.TrimSpace(stderr.String()),
		}, "\n"))
		if details != "" {
			return nil, fmt.Errorf("%s: %w: %s", executable, err, details)
		}
		return nil, fmt.Errorf("%s: %w", executable, err)
	}
	return stdout.Bytes(), nil
}

type WindowsPlatform struct {
	Runner   CommandRunner
	StateDir string
}

func NewWindowsReconciler(stateDir string, emit EventFunc) (*Reconciler, error) {
	platform, err := NewWindowsPlatform(stateDir)
	if err != nil {
		return nil, err
	}
	return &Reconciler{
		Adapters: platform,
		Firewall: platform,
		Policies: platform,
		State:    FileStateStore{Path: filepath.Join(stateDir, "adapter-dns.json")},
		Emit:     emit,
	}, nil
}

func NewWindowsPlatform(stateDir string) (*WindowsPlatform, error) {
	if stateDir == "" {
		return nil, errors.New("state directory must not be empty")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	return &WindowsPlatform{Runner: execCommandRunner{}, StateDir: stateDir}, nil
}

func (p *WindowsPlatform) ListAdapters(ctx context.Context) ([]Adapter, error) {
	const script = `
$ErrorActionPreference = 'Stop'
$result = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
  $v4 = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  $v6 = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
  [pscustomobject]@{
    ID = [string]$_.InterfaceGuid
    Name = [string]$_.Name
    Up = ($_.Status -eq 'Up')
    IPv4DNS = @($v4)
    IPv6DNS = @($v6)
  }
})
ConvertTo-Json -InputObject $result -Depth 4 -Compress
`
	output, err := p.run(ctx, script, nil)
	if err != nil {
		return nil, err
	}
	var adapters []Adapter
	if strings.TrimSpace(string(output)) == "null" {
		return adapters, nil
	}
	if err := json.Unmarshal(output, &adapters); err != nil {
		return nil, fmt.Errorf("decode adapter inventory: %w", err)
	}
	return adapters, nil
}

func (p *WindowsPlatform) SetDNS(ctx context.Context, id, family string, servers []string) error {
	if family != "IPv4" && family != "IPv6" {
		return fmt.Errorf("unsupported DNS address family %q", family)
	}
	payload := map[string]any{"ID": id, "Family": family, "Servers": servers}
	const script = `
$ErrorActionPreference = 'Stop'
$p = ConvertFrom-Json -InputObject $env:GUARDIAN_PAYLOAD
$guid = [guid]::Empty
if (-not [guid]::TryParse([string]$p.ID, [ref]$guid)) { throw 'invalid adapter ID' }
$adapter = Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceGuid -eq $guid } | Select-Object -First 1
if ($null -eq $adapter) { throw 'network adapter no longer exists' }
if (@($p.Servers).Count -eq 0) {
  Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $p.Family -ResetServerAddresses -ErrorAction Stop
} else {
  Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $p.Family -ServerAddresses @($p.Servers) -ErrorAction Stop
}
`
	_, err := p.run(ctx, script, payload)
	return err
}

func (p *WindowsPlatform) ReconcileFirewall(ctx context.Context, rules []Rule) (bool, error) {
	const script = `
$ErrorActionPreference = 'Stop'
$payload = ConvertFrom-Json -InputObject $env:GUARDIAN_PAYLOAD
$expected = @{}
$changed = $false
function Get-RemoteAddresses($rule) {
  if ($rule.RemoteAddress -eq 'any') { return @('Any') }
  if ($rule.RemoteAddress -eq 'nonloopback') {
    return @('0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255', '::-::', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
  }
  return @([string]$rule.RemoteAddress)
}
foreach ($spec in @($payload.Rules)) {
  $name = 'Guardian-' + [string]$spec.Name
  $addresses = @(Get-RemoteAddresses $spec | Sort-Object)
  $expected[$name] = $true
  $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
  $matches = $false
  if ($existing.Count -eq 1) {
    $item = $existing[0]
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $item
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $item
    $currentAddresses = @($address.RemoteAddress | ForEach-Object { [string]$_ } | Sort-Object)
    $matches = ($item.Enabled -eq 'True' -and $item.Direction -eq 'Outbound' -and $item.Action -eq 'Block' -and $item.Profile -eq 'Any' -and
      [string]$port.Protocol -eq [string]$spec.Protocol -and [string]$port.RemotePort -eq [string]$spec.RemotePort -and
      ($currentAddresses -join ',') -eq ($addresses -join ','))
  }
  if (-not $matches) {
    if ($existing.Count -gt 0) { $existing | Remove-NetFirewallRule -ErrorAction Stop }
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol ([string]$spec.Protocol) -RemotePort ([string]$spec.RemotePort) -RemoteAddress $addresses -ErrorAction Stop | Out-Null
    $changed = $true
  }
}
$stale = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'Guardian-*' -ErrorAction SilentlyContinue |
  Where-Object { -not $expected.ContainsKey($_.Name) })
if ($stale.Count -gt 0) { $stale | Remove-NetFirewallRule -ErrorAction Stop; $changed = $true }
ConvertTo-Json -InputObject $changed -Compress
`
	output, err := p.run(ctx, script, map[string]any{"Rules": rules})
	if err != nil {
		return false, err
	}
	var changed bool
	if err := json.Unmarshal(output, &changed); err != nil {
		return false, fmt.Errorf("decode firewall reconciliation result: %w", err)
	}
	return changed, nil
}

func (p *WindowsPlatform) RemoveFirewall(ctx context.Context, prefix string) error {
	if prefix != rulePrefix {
		return errors.New("refusing to remove firewall rules outside the Guardian prefix")
	}
	const script = `
$ErrorActionPreference = 'Stop'
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'Guardian-*' -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) { $rules | Remove-NetFirewallRule -ErrorAction Stop }
`
	_, err := p.run(ctx, script, nil)
	return err
}

func (p *WindowsPlatform) FirewallRuleNames(ctx context.Context) ([]string, error) {
	const script = `
$ErrorActionPreference = 'Stop'
$names = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'Guardian-*' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name })
ConvertTo-Json -InputObject $names -Compress
`
	output, err := p.run(ctx, script, nil)
	if err != nil {
		return nil, err
	}
	var names []string
	if strings.TrimSpace(string(output)) == "null" {
		return names, nil
	}
	if err := json.Unmarshal(output, &names); err != nil {
		return nil, fmt.Errorf("decode Guardian firewall rule names: %w", err)
	}
	return names, nil
}

func (p *WindowsPlatform) ReconcileBrowserPolicies(ctx context.Context) (bool, error) {
	backup := filepath.Join(p.StateDir, "browser-policy-backup.json")
	const script = `
$ErrorActionPreference = 'Stop'
$backupPath = $env:GUARDIAN_POLICY_BACKUP
$backup = [ordered]@{ Registry = @(); Firefox = @() }
if (Test-Path -LiteralPath $backupPath) {
  $loaded = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
  $backup.Registry = @($loaded.Registry)
  $backup.Firefox = @($loaded.Firefox)
}
$registryPaths = @('SOFTWARE\Policies\Google\Chrome', 'SOFTWARE\Policies\Microsoft\Edge')
foreach ($subkey in $registryPaths) {
  if (-not (@($backup.Registry | Where-Object { $_.Path -eq $subkey }).Count)) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkey)
    $entry = [ordered]@{ Path = $subkey; KeyExists = ($null -ne $key); ValueExists = $false; Value = $null; Kind = 'String' }
    if ($null -ne $key) {
      try {
        $entry.ValueExists = @($key.GetValueNames()) -contains 'DnsOverHttpsMode'
        if ($entry.ValueExists) {
          $entry.Value = $key.GetValue('DnsOverHttpsMode', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
          $entry.Kind = [string]$key.GetValueKind('DnsOverHttpsMode')
        }
      } finally { $key.Close() }
    }
    $backup.Registry += [pscustomobject]$entry
  }
}
$programDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { $_ } | Select-Object -Unique
foreach ($root in $programDirs) {
  $firefox = Join-Path $root 'Mozilla Firefox\distribution\policies.json'
  if (-not (Test-Path (Split-Path -Parent $firefox))) { continue }
  if (-not (@($backup.Firefox | Where-Object { $_.Path -eq $firefox }).Count)) {
    $exists = Test-Path -LiteralPath $firefox
    $content = if ($exists) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($firefox)) } else { '' }
    $backup.Firefox += [pscustomobject]@{ Path = $firefox; Exists = $exists; Content = $content }
  }
}
$json = ConvertTo-Json -InputObject $backup -Depth 8
$tmp = $backupPath + '.tmp'
[IO.File]::WriteAllText($tmp, $json, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $tmp -Destination $backupPath -Force

$changed = $false
foreach ($subkey in $registryPaths) {
  $path = 'HKLM:\' + $subkey
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null; $changed = $true }
  $current = Get-ItemProperty -Path $path -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
  if ($null -eq $current -or $current.DnsOverHttpsMode -ne 'off') {
    New-ItemProperty -Path $path -Name DnsOverHttpsMode -PropertyType String -Value 'off' -Force | Out-Null
    $changed = $true
  }
}
foreach ($root in $programDirs) {
  $firefox = Join-Path $root 'Mozilla Firefox\distribution\policies.json'
  if (-not (Test-Path (Split-Path -Parent $firefox))) { continue }
  $policy = '{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}'
  if (-not (Test-Path -LiteralPath $firefox) -or [IO.File]::ReadAllText($firefox) -ne $policy) {
    [IO.File]::WriteAllText($firefox, $policy, [Text.UTF8Encoding]::new($false))
    $changed = $true
  }
}
ConvertTo-Json -InputObject $changed -Compress
`
	output, err := p.run(ctx, script, map[string]any{"PolicyBackup": backup})
	if err != nil {
		return false, err
	}
	var changed bool
	if err := json.Unmarshal(output, &changed); err != nil {
		return false, fmt.Errorf("decode browser-policy result: %w", err)
	}
	return changed, nil
}

func (p *WindowsPlatform) RemoveBrowserPolicies(ctx context.Context) error {
	backup := filepath.Join(p.StateDir, "browser-policy-backup.json")
	const script = `
$ErrorActionPreference = 'Stop'
$backupPath = $env:GUARDIAN_POLICY_BACKUP
if (-not (Test-Path -LiteralPath $backupPath)) { exit 0 }
$backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
foreach ($entry in @($backup.Registry)) {
  $path = 'HKLM:\' + [string]$entry.Path
  if ($entry.ValueExists) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name DnsOverHttpsMode -PropertyType ([string]$entry.Kind) -Value $entry.Value -Force | Out-Null
  } elseif (Test-Path $path) {
    Remove-ItemProperty -Path $path -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
    if (-not $entry.KeyExists -and -not (Get-ChildItem -Path $path -ErrorAction SilentlyContinue)) {
      Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }
  }
}
foreach ($entry in @($backup.Firefox)) {
  $path = [string]$entry.Path
  if ($entry.Exists) {
    [IO.File]::WriteAllBytes($path, [Convert]::FromBase64String([string]$entry.Content))
  } else {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  }
}
Remove-Item -LiteralPath $backupPath -Force
`
	_, err := p.run(ctx, script, map[string]any{"PolicyBackup": backup})
	return err
}

func (p *WindowsPlatform) run(ctx context.Context, script string, payload any) ([]byte, error) {
	if p == nil || p.Runner == nil {
		return nil, errors.New("Windows command runner is not configured")
	}
	encodedPayload := ""
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode PowerShell arguments: %w", err)
		}
		encodedPayload = string(data)
	}
	wrappedScript := "$ErrorActionPreference = 'Stop'\ntry {\n" + script + "\n} catch {\n[Console]::Error.WriteLine($_.ToString())\nexit 1\n}\n"
	encodedScript := base64.StdEncoding.EncodeToString(encodePowerShell(wrappedScript))
	return p.Runner.Run(ctx, "powershell.exe", []string{
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedScript,
	}, []string{"GUARDIAN_PAYLOAD=" + encodedPayload, "GUARDIAN_POLICY_BACKUP=" + p.StateDir + `\browser-policy-backup.json`})
}

func encodePowerShell(script string) []byte {
	units := utf16.Encode([]rune(script))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		data[i*2] = byte(unit)
		data[i*2+1] = byte(unit >> 8)
	}
	return data
}

func mergeEnv(base, extra []string) []string {
	values := make(map[string]string, len(base)+len(extra))
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToUpper(name)] = name + "=" + value
		}
	}
	for _, entry := range extra {
		name, _, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToUpper(name)] = entry
		}
	}
	merged := make([]string, 0, len(values))
	for _, entry := range values {
		merged = append(merged, entry)
	}
	return merged
}

func InstallWatchdog(ctx context.Context, executable string) error {
	if executable == "" || !filepath.IsAbs(executable) {
		return errors.New("watchdog executable path must be absolute")
	}
	task := `"` + executable + `" repair`
	_, err := (execCommandRunner{}).Run(ctx, "schtasks.exe", []string{
		"/Create", "/TN", "GuardianWatchdog", "/SC", "MINUTE", "/MO", "1",
		"/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", task, "/F",
	}, nil)
	if err != nil {
		return fmt.Errorf("install scheduled watchdog: %w", err)
	}
	return nil
}

func RemoveWatchdog(ctx context.Context) error {
	const script = `
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName 'GuardianWatchdog' -ErrorAction SilentlyContinue
if ($null -ne $task) { Unregister-ScheduledTask -TaskName 'GuardianWatchdog' -Confirm:$false -ErrorAction Stop }
`
	if _, err := (execCommandRunner{}).Run(ctx, "powershell.exe", []string{
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand",
		base64.StdEncoding.EncodeToString(encodePowerShell(script)),
	}, nil); err != nil {
		return fmt.Errorf("remove scheduled watchdog: %w", err)
	}
	return nil
}

func SetServiceSecurityDescriptor(ctx context.Context, serviceName string) error {
	if serviceName != "GuardianDNS" {
		return errors.New("refusing to change an unexpected service")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	const serviceACL = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
	descriptor, err := windows.SecurityDescriptorFromString(serviceACL)
	if err != nil {
		return fmt.Errorf("build service security descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read service DACL from descriptor: %w", err)
	}
	err = windows.SetNamedSecurityInfo(serviceName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("set service DACL: %w", err)
	}
	if err := takeOwnershipOfService(serviceName); err != nil {
		return fmt.Errorf("take ownership of service to repair its DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(serviceName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("set service DACL after taking ownership: %w", err)
	}
	return nil
}

// An existing service may deny WRITE_DAC even to Administrators. Windows
// permits its owner to replace the DACL, so enable the documented ownership
// privilege only for the operation and restore the prior token state.
func takeOwnershipOfService(serviceName string) (retErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read installer account SID: %w", err)
	}
	privilegeName, err := windows.UTF16PtrFromString("SeTakeOwnershipPrivilege")
	if err != nil {
		return err
	}
	var privilege windows.LUID
	if err := windows.LookupPrivilegeValue(nil, privilegeName, &privilege); err != nil {
		return fmt.Errorf("look up SeTakeOwnershipPrivilege: %w", err)
	}
	enable := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       privilege,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	var previous windows.Tokenprivileges
	var returned uint32
	setLastError.Call(0)
	if err := windows.AdjustTokenPrivileges(token, false, &enable, uint32(unsafe.Sizeof(previous)), &previous, &returned); err != nil {
		return fmt.Errorf("enable SeTakeOwnershipPrivilege: %w", err)
	}
	defer func() {
		if err := windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore installer token privileges: %w", err))
		}
	}()
	if err := windows.GetLastError(); err != nil {
		return fmt.Errorf("enable SeTakeOwnershipPrivilege: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(serviceName, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		return fmt.Errorf("set service owner to the elevated installer account: %w", err)
	}
	return nil
}

func Repair(ctx context.Context, stateDir string, cfg *config.Config, emit EventFunc) error {
	reconciler, err := NewWindowsReconciler(stateDir, emit)
	if err != nil {
		return err
	}
	_, err = reconciler.Reconcile(ctx, cfg)
	return err
}

func Remove(ctx context.Context, stateDir string) error {
	reconciler, err := NewWindowsReconciler(stateDir, nil)
	if err != nil {
		return err
	}
	return reconciler.Remove(ctx)
}
