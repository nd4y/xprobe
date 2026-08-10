'use strict';
// Probe control-plane UI. All target-set and provisioning logic lives in the
// backend; this renders state and collects form input.
//
// Views (hash routed): #/ — the point list, #/p/<name> — one point's page.
// A full page instead of a dialog: the target table is large, and nesting it
// into a modal produced scroll-in-scroll.

const MODES = ['tcp', 'tunnel', 'status', 'download'];
// The wire format and the metric label keep `status` (dashboards depend on
// it); the UI calls the check `http` — that is what it actually does.
const MODE_LABEL = { tcp: 'tcp', tunnel: 'tunnel', status: 'http', download: 'download' };
const MODE_HINT = {
  tcp: 'connect + TLS handshake to the inbound, no core involved — the latency floor',
  tunnel: 'the same handshake performed by a core: differs from tcp only by the core in the path',
  status: 'HTTP request through the config; minus tcp it gives the latency added past the entry',
  download: 'how much data the tunnel lets through before it is cut',
};
const DEF_INT = { tcp: 300, tunnel: 300, status: 300, download: 1800 };
// Which target set each check reads. The names are historical — renaming a
// live wire field buys nothing.
const MODE_FIELD = { tcp: 'tcp_remarks', tunnel: 'tunnel_remarks',
                     status: 'check_remarks', download: 'load_remarks' };

function el(tag, attrs = {}, kids = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n[k] = v;
    else if (k === 'checked') n.checked = v;
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of [].concat(kids)) if (kid != null) n.append(kid);
  return n;
}

async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    headers: { 'content-type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new Error((data && data.detail) || `HTTP ${res.status}`);
  return data;
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.hidden = false;
  t.classList.remove('show');
  void t.offsetWidth;                 // restart the animation
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, 2600);
}

function dialog(title, body, actions) {
  const d = document.getElementById('dialog');
  d.replaceChildren(
    el('h2', {}, title),
    ...[].concat(body),
    el('div', { class: 'dialog-actions' }, [
      ...actions,
      el('button', { onclick: () => d.close() }, 'Close'),
    ]),
  );
  d.showModal();
  return d;
}

function confirmDialog(title, text, actionLabel, onConfirm) {
  const d = document.getElementById('dialog');
  const go = el('button', { class: 'danger filled', onclick: async () => { d.close(); await onConfirm(); } }, actionLabel);
  d.replaceChildren(
    el('h2', {}, title),
    el('p', { class: 'muted' }, text),
    el('div', { class: 'dialog-actions' }, [
      el('button', { onclick: () => d.close() }, 'Cancel'), go,
    ]),
  );
  d.showModal();
}

function chip(text, cls = '') {
  return el('span', { class: `chip ${cls}` }, text);
}

function ago(seconds) {
  if (seconds === null || seconds === undefined) return 'never';
  const s = Math.round(seconds);
  if (s < 90) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

// The threshold comes from the backend, derived from this point's own
// cadence — a point on a slower schedule is not late for being slow.
const HEALTH_CLASS = {
  online: 'on', 'standing by': 'tonal', late: 'warnchip',
  'no metrics': 'off', offline: 'off', never: 'off',
};

function healthChip(h) {
  if (!h) return null;
  if (h.state === 'never') return chip('never seen', 'off');
  const detail = h.state === 'online' || h.state === 'late'
    ? ago(h.metrics_ago ?? h.seen_ago)
    : ago(h.seen_ago);
  return chip(`${h.state} · ${detail}`, HEALTH_CLASS[h.state] || '');
}

function mswitch(checked, attrs = {}) {
  const input = el('input', { type: 'checkbox', checked, ...attrs });
  const wrap = el('label', { class: 'switch' }, [input, el('span', { class: 'track' })]);
  wrap.input = input;
  return wrap;
}

function render(...nodes) {
  const box = document.getElementById('main');
  box.replaceChildren(...nodes);
  // A tiny entrance for every view change; CSS handles motion preferences.
  box.classList.remove('view-enter');
  void box.offsetWidth;
  box.classList.add('view-enter');
}

// ── routing ──────────────────────────────────────────────────────────────────

async function route() {
  const m = location.hash.match(/^#\/p\/(.+)$/);
  try {
    if (m) await pointView(decodeURIComponent(m[1]));
    else await listView();
  } catch (e) {
    render(el('div', { class: 'signin' }, String(e.message)));
  }
}
window.addEventListener('hashchange', route);

async function main() {
  const me = await api('/me').catch(() => ({ authenticated: false }));
  const who = document.getElementById('who');
  if (!me.authenticated || !me.owner) {
    who.replaceChildren();
    render(el('div', { class: 'signin' }, [
      el('p', {}, me.authenticated ? 'Administrator rights required.' : 'Sign-in required.'),
      el('button', { class: 'filled', onclick: () => { location.href = '/auth/login'; } }, 'Sign in'),
    ]));
    return;
  }
  who.replaceChildren(el('span', {}, me.name || ''));
  await route();
}

// ── list view ────────────────────────────────────────────────────────────────

async function listView() {
  render(el('div', { class: 'loader' }, 'loading…'));
  const points = await api('/admin/points');

  const toolbar = el('div', { class: 'toolbar' }, [
    el('h2', { class: 'grow' }, `Vantage points (${points.length})`),
    el('button', { class: 'tonal', onclick: showCores }, 'Cores'),
    el('button', { class: 'tonal', onclick: showTokens }, 'Enroll tokens'),
    el('button', { class: 'filled', onclick: addPoint }, '+ Add point'),
  ]);

  const cards = points.map((p) => {
    const geo = [p.city, p.country].filter(Boolean).join(', ');
    const modes = MODES.filter((m) => p.modes[m]);
    return el('div', {
      class: 'card point-card',
      onclick: () => { location.hash = `#/p/${encodeURIComponent(p.name)}`; },
    }, [
      el('div', { class: 'row' }, [
        el('span', { class: 'point-name grow' }, p.name),
        p.enabled ? null : chip('disabled', 'off'),
        healthChip(p.health),
      ]),
      el('div', { class: 'muted' }, [geo, p.isp].filter(Boolean).join(' · ') || 'location pending'),
      el('div', { class: 'chips' }, [
        chip(`v${p.version}`),
        chip(p.vantage, 'tonal'),
        p.auto ? chip('auto-enrolled') : null,
        ...modes.map((m) => chip(`${MODE_LABEL[m]} / ${(p.intervals && p.intervals[m]) || DEF_INT[m]}s`)),
      ]),
    ]);
  });

  render(toolbar, el('div', { class: 'points' },
    cards.length ? cards : [el('div', { class: 'muted' }, 'No points yet — add one or share the enroll token.')]));
}

// ── point view ───────────────────────────────────────────────────────────────

async function pointView(name) {
  render(el('div', { class: 'loader' }, 'loading…'));
  const [p, hosts] = await Promise.all([
    api(`/admin/points/${encodeURIComponent(name)}`),
    api('/admin/panel/hosts'),
  ]);

  // — header —
  const enabled = mswitch(p.enabled, { title: 'enabled' });
  const head = el('div', { class: 'toolbar' }, [
    el('button', { class: 'icon', onclick: () => { location.hash = '#/'; } }, '←'),
    el('h2', { class: 'mono' }, p.name),
    chip(`v${p.version}`),
    healthChip(p.health),
    p.auto ? chip('auto-enrolled') : null,
    el('span', { class: 'grow' }),
    el('span', { class: 'muted' }, 'enabled'), enabled,
  ]);

  // — location —
  const country = el('input', { value: p.country || '' });
  const city = el('input', { value: p.city || '' });
  const isp = el('input', { value: p.isp || '', placeholder: 'optional' });
  const vantage = el('select', {}, ['home', 'node'].map((v) =>
    el('option', { value: v, ...(p.vantage === v ? { selected: '' } : {}) }, v)));
  const pinGeo = mswitch(p.pin_geo);
  const h = p.health || {};
  const healthCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Liveness'),
      el('div', { class: 'muted' },
        `Expected every ${h.expect_every} s — this point's own push interval, not a fixed number.`),
    ]),
    el('div', { class: 'grid' }, [
      el('div', {}, [el('div', { class: 'muted' }, 'last heard from'),
        el('b', {}, ago(h.seen_ago))]),
      el('div', {}, [el('div', { class: 'muted' }, 'last metrics'),
        el('b', {}, h.expects_metrics ? ago(h.metrics_ago) : 'not expected')]),
      el('div', {}, [el('div', { class: 'muted' }, 'state'), healthChip(h) || '—']),
    ]),
  ]);

  const locationCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Location'),
      el('div', { class: 'muted' },
        p.pin_geo ? 'Pinned manually — the probe’s self-detection is ignored.'
                  : `Detected by the probe: ${[p.city, p.isp].filter(Boolean).join(', ') || 'nothing yet'}.`),
    ]),
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'country'), country]),
      el('label', { class: 'field' }, [el('span', {}, 'city'), city]),
      el('label', { class: 'field' }, [el('span', {}, 'network (ISP)'), isp]),
      el('label', { class: 'field' }, [el('span', {}, 'vantage'), vantage]),
    ]),
    el('div', { class: 'row' }, [pinGeo, el('span', { class: 'muted' }, 'pin location manually')]),
  ]);

  // — checks —
  const modeBoxes = {}; const intBoxes = {};
  // Which cores this node carries, as the probe reported them, and any check
  // pointed at one it does not have.
  // What this node reports it can run, plus what the catalogue lets it fetch.
  const reported = p.xray_versions || [];
  const catalogue = (await api('/admin/cores')).cores.map((c) => c.version);
  const avail = [...new Set([...reported, ...catalogue])].sort();
  const coreBoxes = {};
  // Only a version that is neither on the node nor fetchable is a problem.
  const badCores = MODES.filter((m) => m !== 'tcp')
    .map((m) => (p.cores && p.cores[m]) || '')
    .filter((v) => v && !avail.includes(v));

  // Volume tolerance: the download check proves how much gets through before
  // the tunnel is cut, so both the source file and the volume are per point.
  const dlUrl = el('input', { value: p.download_url || '', placeholder: 'default source' });
  const dlMiB = el('input', { type: 'number', min: '0', step: '1',
    value: p.download_min_bytes ? String(Math.round(p.download_min_bytes / 1048576)) : '',
    placeholder: '0.5' });

  const checksCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Checks'),
      el('div', { class: 'muted' }, 'Each check runs on its own schedule; tcp and http run concurrently, so their latencies are comparable.'),
    ]),
    ...MODES.map((m) => {
      const sw = mswitch(!!p.modes[m]);
      const iv = el('input', { type: 'number', min: '10', step: '10',
        value: String((p.intervals && p.intervals[m]) || DEF_INT[m]) });
      modeBoxes[m] = sw.input; intBoxes[m] = iv;
      const row = [
        sw,
        el('span', { class: 'name' }, MODE_LABEL[m]),
        el('span', { class: 'muted grow' }, MODE_HINT[m]),
        el('span', { class: 'every' }, [el('span', { class: 'muted' }, 'every'), iv,
          el('span', { class: 'muted' }, 's')]),
      ];
      // tcp opens a socket and a TLS handshake itself — no core is involved,
      // so offering it a core version would be a lie.
      if (m !== 'tcp') {
        const cur = (p.cores && p.cores[m]) || '';
        const opts = [el('option', { value: '' }, 'image default')];
        for (const v of avail) {
          opts.push(el('option', { value: v, ...(cur === v ? { selected: '' } : {}) }, v));
        }
        if (cur && !avail.includes(cur)) {
          opts.push(el('option', { value: cur, selected: '' }, `${cur} — not on this node`));
        }
        const sel = el('select', {}, opts);
        coreBoxes[m] = sel;
        row.push(el('span', { class: 'every' }, [el('span', { class: 'muted' }, 'core'), sel]));
      }
      return el('div', { class: 'check-row' }, row);
    }),
    el('div', { class: 'muted' }, reported.length
      ? `On this node: ${reported.join(', ')}. Fetchable from the catalogue: ${
          catalogue.filter((v) => !reported.includes(v)).join(', ') || 'nothing more'}.`
      : 'This node has not reported its cores yet.'),
    ...(badCores.length ? [el('div', { class: 'warn' }, [
      el('b', {}, 'A check is set to a core this node does not have: '),
      badCores.join(', '),
      el('div', { class: 'muted' }, 'That check cannot run at all — the probe refuses to substitute another core, because an answer from the wrong version is worse than no answer.'),
    ])] : []),
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'volume to push, MiB'), dlMiB]),
      el('label', { class: 'field' }, [el('span', {}, 'volume test source'), dlUrl]),
    ]),
    el('div', { class: 'muted' },
      'The source file must be at least as large as the volume — the check proves the tunnel survives that much, not how fast it is.'),
  ]);

  // — targets: one table, a checkbox column per check —
  const sels = {
    ...Object.fromEntries(MODES.map((m) => [m, new Set(p[MODE_FIELD[m]] || [])])),
  };
  const search = el('input', { type: 'search', placeholder: 'Filter hosts…' });
  const tbody = el('tbody');
  const allBoxes = {};
  for (const m of MODES) {
    allBoxes[m] = el('input', { type: 'checkbox', title: 'toggle all visible',
      onchange: () => {
        visibleHosts().forEach((h) =>
          allBoxes[m].checked ? sels[m].add(h.remark) : sels[m].delete(h.remark));
        renderRows();
      } });
  }

  function visibleHosts() {
    const q = search.value.trim().toLowerCase();
    return hosts.filter((h) =>
      !q || h.remark.toLowerCase().includes(q) || h.inbound.toLowerCase().includes(q));
  }
  function renderRows() {
    const vis = visibleHosts();
    tbody.replaceChildren(...vis.map((h) => el('tr', {}, [
      el('td', {}, [h.remark, el('span', { class: 'in' }, h.inbound)]),
      ...MODES.map((m) => el('td', { class: 'c' },
        el('input', { type: 'checkbox', checked: sels[m].has(h.remark),
          onchange: (e) => {
            e.target.checked ? sels[m].add(h.remark) : sels[m].delete(h.remark);
            syncAll();
          } }))),
    ])));
    syncAll();
  }
  function syncAll() {
    const vis = visibleHosts();
    for (const m of MODES) {
      allBoxes[m].checked = vis.length > 0 && vis.every((h) => sels[m].has(h.remark));
    }
  }
  search.oninput = renderRows;
  renderRows();

  const missing = p.missing_targets || [];
  const targetsCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Targets'),
      el('div', { class: 'muted' },
        'Each check has its own target set. tcp and http are cheap — the full set is fine; download is heavy, keep its set short.'),
    ]),
    // A target the point's account cannot see is served as nothing: the check
    // would look healthy while probing less than asked.
    missing.length ? el('div', { class: 'warn' }, [
      el('b', {}, `${missing.length} target(s) not visible to this point: `),
      missing.join(', '),
      el('div', { class: 'muted' }, 'Its panel account does not carry these hosts — check the account’s squad.'),
    ]) : null,
    el('div', { class: 'targets-tools' }, [search]),
    el('div', { class: 'targets' }, el('div', { class: 'scroll' },
      el('table', {}, [
        el('thead', {}, el('tr', {}, [
          el('th', {}, 'Host'),
          ...MODES.map((m) => el('th', { class: 'c' }, [`${MODE_LABEL[m]} `, allBoxes[m]])),
        ])),
        tbody,
      ]))),
  ]);

  // — deployment & maintenance —
  const maintCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Deployment'),
      el('div', { class: 'muted' },
        'An enroll token lets this node fetch its secret and fetch it again after losing storage — and can be revoked for this node alone. A run command embeds a fresh secret instead, and the running probe must be restarted with it.'),
    ]),
    el('div', { class: 'row' }, [
      el('button', { class: 'tonal', onclick: () => issueToken(name) }, 'Enroll token'),
      el('button', { class: 'tonal', onclick: () =>
        confirmDialog('Issue a run command?',
          'This rotates the point’s secret: the currently running probe keeps working until its next config poll, then needs the new command.',
          'Issue', async () => {
            const r = await api(`/admin/points/${encodeURIComponent(name)}/rotate-secret`, { method: 'POST' });
            showCommands('Run command', r.install);
          }) }, 'Run command'),
      el('span', { class: 'grow' }),
      el('button', { class: 'outlined danger', onclick: () =>
        confirmDialog(`Remove ${name}?`,
          'The point is removed from the control plane only. Panel accounts and squads stay in place.',
          'Remove', async () => {
            await api(`/admin/points/${encodeURIComponent(name)}`, { method: 'DELETE' });
            toast('Point removed'); location.hash = '#/';
          }) }, 'Remove point'),
    ]),
  ]);

  // — save bar —
  const save = el('button', { class: 'filled', onclick: async (e) => {
    e.target.disabled = true;
    try {
      await api(`/admin/points/${encodeURIComponent(name)}`, {
        method: 'PATCH',
        body: {
          vantage: vantage.value, country: country.value, city: city.value, isp: isp.value,
          pin_geo: pinGeo.input.checked, enabled: enabled.input.checked,
          modes: Object.fromEntries(MODES.map((m) => [m, modeBoxes[m].checked])),
          intervals: Object.fromEntries(MODES.map((m) => [m, Number(intBoxes[m].value) || 0])),
          cores: Object.fromEntries(Object.entries(coreBoxes)
            .map(([m, sel]) => [m, sel.value]).filter(([, v]) => v)),
          download_url: dlUrl.value.trim(),
          download_min_bytes: Math.round((Number(dlMiB.value) || 0) * 1048576),
        },
      });
      await api(`/admin/points/${encodeURIComponent(name)}/set`, {
        method: 'POST',
        body: Object.fromEntries(MODES.map((m) => [MODE_FIELD[m], [...sels[m]]])),
      });
      toast('Saved — the probe restarts with the new version');
      await pointView(name);
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Save changes');
  const savebar = el('div', { class: 'savebar' }, el('div', { class: 'inner' }, [
    el('span', { class: 'muted grow' }, 'Saving bumps the document version; the probe picks it up within a minute.'),
    save,
  ]));

  render(head, el('div', { class: 'stack' },
    [healthCard, locationCard, checksCard, targetsCard, maintCard]), savebar);
}

// ── dialogs ──────────────────────────────────────────────────────────────────

// The core catalogue: which xray versions exist and what each must hash to.
// Policy, not payload — a node fetches from a location built into itself and
// verifies against this, so the control plane never ships code.
async function showCores() {
  const { cores, relay } = await api('/admin/cores');
  const rows = cores.map((c) => el('div', { class: 'check-row' }, [
    el('span', { class: 'grow' }, [
      el('b', {}, c.version),
      el('div', { class: 'in' }, c.sha256),
    ]),
    el('button', { class: 'small danger', onclick: () =>
      confirmDialog(`Remove ${c.version} from the catalogue?`,
        'Nodes that already fetched it keep it — this stops new fetches, it does not reach onto the nodes.',
        'Remove', async () => {
          await api(`/admin/cores/${encodeURIComponent(c.version)}`, { method: 'DELETE' });
          toast('Removed'); showCores();
        }) }, 'Remove'),
  ]));
  const relaySwitch = mswitch(relay);
  relaySwitch.input.onchange = async () => {
    await api('/admin/cores/relay', { method: 'POST',
      body: { enabled: relaySwitch.input.checked } });
    toast(relaySwitch.input.checked ? 'Relay on' : 'Relay off');
  };
  const version = el('input', { placeholder: 'v26.7.28' });
  const sha = el('input', { placeholder: '64 hex characters' });
  const add = el('button', { class: 'filled', onclick: async (e) => {
    e.target.disabled = true;
    try {
      await api('/admin/cores', { method: 'POST',
        body: { version: version.value.trim(), sha256: sha.value.trim() } });
      toast('Added'); showCores();
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Add');
  dialog('xray cores', [
    el('p', { class: 'muted' }, 'A node fetches a core it does not carry from the official XTLS release and refuses it unless the checksum matches. The download location is built into the probe — only the version and its checksum come from here.'),
    ...(rows.length ? rows : [el('div', { class: 'muted' }, 'Nothing in the catalogue — checks can only use the cores baked into the image.')]),
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'version'), version]),
      el('label', { class: 'field' }, [el('span', {}, 'sha256 of Xray-linux-64.zip'), sha]),
    ]),
    el('div', { class: 'secret' },
      'curl -sL https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-linux-64.zip \\\n  | sha256sum'),
    el('div', { class: 'row' }, [relaySwitch,
      el('span', { class: 'muted' }, 'fetch cores for nodes that cannot reach the release')]),
    el('div', { class: 'muted' },
      'Nodes always try the official release first. Relaying costs this machine the bandwidth, and changes nothing about trust — the node checks the same checksum either way.'),
  ], [add]);
}

// One token per node. A node keeps its token — it is what lets it come back
// after losing its storage — so revoking one has to end that node's access
// and nobody else's.
async function showTokens() {
  const tokens = await api('/admin/enroll-tokens');
  const rows = tokens.map((t) => {
    // The chip carries the revoked state; this line says what the token is for.
    const state = t.point ? `bound to ${t.point}` : 'not used yet';
    return el('div', { class: 'check-row' }, [
      el('span', { class: 'grow' }, [
        el('b', {}, t.label || '(no label)'),
        el('span', { class: 'in' }, ` ${t.id}`),
        el('div', { class: 'muted' }, state),
      ]),
      t.revoked ? chip('revoked', 'off') : el('button', { class: 'small danger', onclick: () =>
        confirmDialog('Revoke this token?',
          `The node can no longer come back after a restart. It keeps running on the secret it already has — disable its point too if you want it to stop now.`,
          'Revoke', async () => {
            await api(`/admin/enroll-tokens/${t.id}/revoke`, { method: 'POST' });
            toast('Revoked'); showTokens();
          }) }, 'Revoke'),
    ]);
  });
  const issue = el('button', { class: 'filled', onclick: () => issueToken() }, '+ Issue token');
  dialog('Enroll tokens', [
    el('p', { class: 'muted' }, 'A node presents its token to get its point’s secret, and again whenever it loses it. Tokens are shown once — only their hashes are kept.'),
    ...(rows.length ? rows : [el('div', { class: 'muted' }, 'No tokens issued yet.')]),
  ], [issue]);
}

async function issueToken(pointName) {
  const label = el('input', { placeholder: 'e.g. Ivan’s NAS' });
  const points = pointName ? [] : await api('/admin/points');
  const bind = pointName ? null : el('select', {}, [
    el('option', { value: '' }, '— create a new point on first use —'),
    ...points.map((p) => el('option', { value: p.name }, p.name)),
  ]);
  const go = el('button', { class: 'filled', onclick: async (e) => {
    e.target.disabled = true;
    try {
      const r = await api('/admin/enroll-tokens', {
        method: 'POST',
        body: { label: label.value.trim(), point: pointName || (bind ? bind.value : '') },
      });
      dialog(`Token ${r.id}`, [
        el('p', { class: 'muted' }, 'Shown once. This node — and only this node — uses it; revoke it to cut the node off.'),
        cmdBlock('docker compose (.env)', r.env),
        cmdBlock('kubernetes', r.kubectl),
      ], []);
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Issue');
  dialog('Issue an enroll token', [
    el('p', { class: 'muted' }, 'One token per node, so it can be taken back from that node alone.'),
    el('label', { class: 'field' }, [el('span', {}, 'label'), label]),
    bind ? el('label', { class: 'field' }, [el('span', {}, 'point'), bind]) : null,
  ], [go]);
}

async function addPoint() {
  const name = el('input', { placeholder: 'e.g. yaroslavl' });
  const country = el('input', { value: '' });
  const city = el('input', {});
  const vantage = el('select', {}, [
    el('option', { value: 'home' }, 'home'), el('option', { value: 'node' }, 'node'),
  ]);
  const create = el('button', { class: 'filled', onclick: async (e) => {
    e.target.disabled = true;
    try {
      const r = await api('/admin/points', {
        method: 'POST',
        body: {
          name: name.value.trim(), country: country.value, city: city.value,
          vantage: vantage.value, check_remarks: [], load_remarks: [],
        },
      });
      showCommands('Point provisioned', r.install,
        () => { location.hash = `#/p/${encodeURIComponent(r.name)}`; });
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Provision');
  dialog('New point', [
    el('p', { class: 'muted' }, 'Creates panel squads, monitoring accounts and the point’s secret. Pick its targets on the point page afterwards.'),
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'name'), name]),
      el('label', { class: 'field' }, [el('span', {}, 'country'), country]),
      el('label', { class: 'field' }, [el('span', {}, 'city'), city]),
      el('label', { class: 'field' }, [el('span', {}, 'vantage'), vantage]),
    ]),
  ], [create]);
}

function cmdBlock(label, text) {
  return el('div', { class: 'cmd' }, [
    el('div', { class: 'row' }, [
      el('span', { class: 'muted grow' }, label),
      el('button', { class: 'small', onclick: () => {
        navigator.clipboard.writeText(text).then(() => toast('Copied'));
      } }, 'Copy'),
    ]),
    el('div', { class: 'secret' }, text),
  ]);
}

function showCommands(title, install, onClose) {
  const d = document.getElementById('dialog');
  dialog(title, [
    el('p', { class: 'muted' }, 'The command embeds the fresh secret and is shown only once. Pick the flavor that matches the node:'),
    cmdBlock('docker', install.docker),
    cmdBlock('kubectl', install.kubectl),
  ], []);
  if (onClose) d.addEventListener('close', onClose, { once: true });
}

main().catch((e) => {
  render(el('div', { class: 'signin' }, String(e.message)));
});
