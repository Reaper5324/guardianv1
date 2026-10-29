const byId = (id) => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = value; };

function render(data) {
  byId('notice').hidden = !data.using_fallback;
  if (data.using_fallback) {
    byId('notice').textContent = 'The primary configuration was unavailable or older. Showing the saved last-known-good configuration.';
  }
  text('version', `v${data.version}`);
  text('service-count', String(data.blocked_services.length));
  text('rule-count', String(data.blocked_domain_count + data.allowed_domain_count));
  text('doh-status', data.block_doh_providers ? 'Filtering on' : 'Not enabled');
  text('config-state', data.using_fallback ? 'Recovery copy' : 'Configuration loaded');
  text('listener', data.listen_addr);
  text('upstream-count', `${data.upstream_count} configured`);
  text('timezone', data.timezone);
  text('updated', `Refreshed ${new Date(data.read_at).toLocaleTimeString()}`);

  const services = byId('services');
  services.replaceChildren();
  if (data.blocked_services.length) {
    for (const service of data.blocked_services) {
      const chip = document.createElement('span');
      chip.className = 'service-chip';
      chip.textContent = service;
      services.append(chip);
    }
  } else {
    const empty = document.createElement('span');
    empty.className = 'empty-copy';
    empty.textContent = 'No built-in service profiles selected.';
    services.append(empty);
  }

  if (data.bedtime_enabled) {
    text('bedtime-start', data.bedtime_start);
    text('bedtime-end', data.bedtime_end);
    text('bedtime-state', data.bedtime_active ? 'Bedtime filtering is active now' : 'Bedtime is scheduled');
    byId('bedtime-dot').classList.toggle('on', data.bedtime_active);
    text('schedule-note', `Configured in ${data.timezone}. Allowlisted domains remain available during bedtime.`);
  } else {
    text('bedtime-start', 'Off');
    text('bedtime-end', 'Off');
    text('bedtime-state', 'No bedtime window configured');
    byId('bedtime-dot').classList.remove('on');
    text('schedule-note', 'Add a bedtime window to block non-allowlisted names during selected hours.');
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
    notice.textContent = `Could not read the local configuration: ${error.message}`;
    text('config-state', 'Unavailable');
    text('updated', 'Refresh the page to try again');
  }
}

refresh();
setInterval(refresh, 30000);
