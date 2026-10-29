const byId = (id) => document.getElementById(id);
const setText = (id, value) => { byId(id).textContent = value; };
const fmtTime = (value) => value ? new Date(value).toLocaleString() : 'Not recorded';

function renderServices(names) {
  const container = byId('services');
  container.replaceChildren();
  if (!names.length) {
    const empty = document.createElement('span');
    empty.className = 'empty-copy';
    empty.textContent = 'No built-in profiles selected.';
    container.append(empty);
    return;
  }
  for (const name of names) {
    const chip = document.createElement('span');
    chip.className = 'service-chip';
    chip.textContent = name;
    container.append(chip);
  }
}

function renderAdapters(adapters) {
  const container = byId('adapters');
  container.replaceChildren();
  if (!adapters.length) {
    const empty = document.createElement('span');
    empty.className = 'empty-copy';
    empty.textContent = 'No adapter details are available.';
    container.append(empty);
    return;
  }
  for (const adapter of adapters) {
    const row = document.createElement('div');
    row.className = 'adapter-row';
    const identity = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = adapter.name || 'Network adapter';
    const state = document.createElement('span');
    state.className = adapter.up ? 'adapter-state online' : 'adapter-state';
    state.textContent = adapter.up ? 'Connected' : 'Disconnected';
    identity.append(name, state);
    const dns = document.createElement('div');
    dns.className = 'adapter-dns';
    dns.textContent = `IPv4 ${adapter.ipv4_dns?.join(', ') || '—'}  ·  IPv6 ${adapter.ipv6_dns?.join(', ') || '—'}`;
    row.append(identity, dns);
    container.append(row);
  }
}

function renderActivity(events) {
  const container = byId('activity-list');
  container.replaceChildren();
  if (!events.length) {
    const empty = document.createElement('span');
    empty.className = 'empty-copy';
    empty.textContent = 'No recent events recorded.';
    container.append(empty);
    return;
  }
  for (const item of [...events].reverse()) {
    const row = document.createElement('div');
    row.className = 'activity-row';
    const message = document.createElement('strong');
    message.textContent = item.summary;
    const time = document.createElement('time');
    time.dateTime = item.time;
    time.textContent = fmtTime(item.time);
    const count = Number(item.repeat_count || 1);
    const repeats = document.createElement('span');
    repeats.className = 'activity-repeat';
    repeats.textContent = count > 1 ? `${count} occurrences` : '';
    row.append(message, time, repeats);
    container.append(row);
  }
}

function render(data) {
  const notice = byId('notice');
  notice.hidden = !data.using_fallback;
  if (data.using_fallback) {
    notice.textContent = 'The primary configuration was unavailable or older. Guardian is using its saved last-known-good copy.';
  }

  byId('service-dot').classList.toggle('offline', !data.dns_listeners_ready);
  setText('service-label', data.dns_listeners_ready ? 'SERVICE ACTIVE' : 'DNS LISTENER ISSUE');
  setText('dns-state', data.dns_listeners_ready ? 'Listening' : 'Unavailable');
  setText('dns-caption', `Guardian DNS · ${data.listen_addr}`);
  setText('blocked-today', String(data.blocked_today));
  setText('version', `v${data.version}`);
  setText('config-caption', data.using_fallback ? 'Using recovery copy' : 'Active revision');
  setText('upstream-state', data.upstream_health || 'Unknown');
  setText('upstream-caption', `${data.upstream_count} encrypted resolver(s) configured`);
  setText('listener', `${data.dns_listeners_ready ? 'Ready' : 'Not ready'} · ${data.listen_addr}`);
  setText('upstream-count', `${data.upstream_count} configured`);
  setText('blocked-count', String(data.blocked_domain_count));
  setText('allowed-count', String(data.allowed_domain_count));
  setText('doh-policy', data.block_doh_providers ? 'Enabled' : 'Off');
  setText('firewall-count', data.firewall_status === 'Rules active' ? `${data.firewall_rule_count} present` : data.firewall_status || 'Unknown');
  setText('timezone', data.timezone || 'System local time');
  setText('remote-enabled', data.remote_enabled ? 'Enabled' : 'Off');
  setText('signature-state', data.remote_enabled ? (data.signature_required ? 'Required' : 'Optional') : 'Not applicable');
  setText('last-sync', data.last_remote_sync ? `${data.last_remote_sync} · ${fmtTime(data.last_remote_sync_at)}` : 'No sync recorded');
  setText('last-drift', data.last_drift ? `${data.last_drift} · ${fmtTime(data.last_drift_at)}` : 'None recorded');
  setText('updated', `Updated ${new Date(data.read_at).toLocaleTimeString()} · started ${fmtTime(data.service_started_at)}`);

  const enforcement = byId('enforcement-state');
  enforcement.textContent = data.dns_listeners_ready && data.firewall_status === 'Rules active' ? 'Enforcement online' : 'Check enforcement';
  enforcement.classList.toggle('warning', !(data.dns_listeners_ready && data.firewall_status === 'Rules active'));
  byId('repair-button').disabled = !data.can_repair;
  byId('uninstall-box').hidden = !data.can_uninstall;
  byId('remote-state').textContent = data.remote_enabled ? 'Configured' : 'Disabled';

  renderServices(data.blocked_services || []);
  renderAdapters(data.adapters || []);
  renderActivity(data.recent_events || []);

  if (data.bedtime_enabled) {
    setText('bedtime-start', data.bedtime_start);
    setText('bedtime-end', data.bedtime_end);
    setText('bedtime-state', data.bedtime_active ? 'Bedtime filtering is active now' : 'Bedtime is scheduled');
    byId('bedtime-dot').classList.toggle('on', data.bedtime_active);
    setText('schedule-note', `Configured in ${data.timezone}. Allowlisted domains remain available during bedtime.`);
  } else {
    setText('bedtime-start', 'Off');
    setText('bedtime-end', 'Off');
    setText('bedtime-state', 'No bedtime window configured');
    byId('bedtime-dot').classList.remove('on');
    setText('schedule-note', 'No bedtime window is configured.');
  }
}

async function refresh() {
  try {
    const response = await fetch('/api/status', { cache: 'no-store', headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    render(await response.json());
  } catch (error) {
    const notice = byId('notice');
    notice.hidden = false;
    notice.textContent = `Could not connect to Guardian: ${error.message}`;
    byId('service-dot').classList.add('offline');
    setText('service-label', 'SERVICE UNAVAILABLE');
    setText('updated', 'Check that the Guardian service is running');
  }
}

byId('repair-button').addEventListener('click', async () => {
  const button = byId('repair-button');
  const result = byId('repair-result');
  button.disabled = true;
  result.textContent = 'Reconciling enforcement…';
  try {
    const response = await fetch('/api/repair', { method: 'POST', cache: 'no-store' });
    if (!response.ok) throw new Error(`Repair failed (${response.status})`);
    result.textContent = 'Repair completed.';
    await refresh();
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

byId('uninstall-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = byId('uninstall-button');
  const result = byId('uninstall-result');
  const passwordInput = byId('parent-password');
  button.disabled = true;
  result.textContent = 'Verifying password…';
  try {
    const response = await fetch('/api/uninstall', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: passwordInput.value })
    });
    if (!response.ok) throw new Error(response.status === 401 ? 'Password was not accepted.' : `Uninstall failed (${response.status})`);
    passwordInput.value = '';
    result.textContent = 'Uninstall requested. Guardian will restore saved DNS and remove its policies.';
    button.disabled = true;
  } catch (error) {
    result.textContent = error.message;
    button.disabled = false;
  }
});

refresh();
setInterval(refresh, 15000);
