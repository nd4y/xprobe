'use strict';
// Probe control-plane UI. All target-set and provisioning logic lives in the
// backend; this renders state and collects form input.
//
// Views (hash routed): #/ — the point list, #/p/<name> — one point's page.
// A full page instead of a dialog: the target table is large, and nesting it
// into a modal produced scroll-in-scroll.

const MODES = ['tcp', 'status', 'download'];
// The wire format and the metric label keep `status` (dashboards depend on
// it); the UI calls the check `http` — that is what it actually does.
const MODE_LABEL = { tcp: 'tcp', status: 'http', download: 'download' };
const MODE_HINT = {
  tcp: 'connect + TLS handshake to the inbound — the latency floor, before the tunnel',
  status: 'HTTP request through the config; minus tcp it gives the latency added past the entry',
  download: 'how much data the tunnel lets through before it is cut',
};
const DEF_INT = { tcp: 300, status: 300, download: 1800 };

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
    el('button', { class: 'tonal', onclick: showEnroll }, 'Enroll token'),
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
        chip(p.enabled ? 'enabled' : 'disabled', p.enabled ? 'on' : 'off'),
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
      return el('div', { class: 'check-row' }, [
        sw,
        el('span', { class: 'name' }, MODE_LABEL[m]),
        el('span', { class: 'muted grow' }, MODE_HINT[m]),
        el('span', { class: 'every' }, [el('span', { class: 'muted' }, 'every'), iv,
          el('span', { class: 'muted' }, 's')]),
      ]);
    }),
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'volume to push, MiB'), dlMiB]),
      el('label', { class: 'field' }, [el('span', {}, 'volume test source'), dlUrl]),
    ]),
    el('div', { class: 'muted' },
      'The source file must be at least as large as the volume — the check proves the tunnel survives that much, not how fast it is.'),
  ]);

  // — targets: one table, a checkbox column per check —
  const sels = {
    tcp: new Set(p.tcp_remarks || []),
    status: new Set(p.check_remarks || []),
    download: new Set(p.load_remarks || []),
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
        'Only a hash of the secret is stored, so a run command comes with a fresh secret — the running probe must be restarted with it.'),
    ]),
    el('div', { class: 'row' }, [
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
          download_url: dlUrl.value.trim(),
          download_min_bytes: Math.round((Number(dlMiB.value) || 0) * 1048576),
        },
      });
      await api(`/admin/points/${encodeURIComponent(name)}/set`, {
        method: 'POST',
        body: { tcp_remarks: [...sels.tcp], check_remarks: [...sels.status],
                load_remarks: [...sels.download] },
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
    [locationCard, checksCard, targetsCard, maintCard]), savebar);
}

// ── dialogs ──────────────────────────────────────────────────────────────────

// Enroll token: a node registers with the control plane using it. One-time
// per node and rotatable — regenerating revokes the old token while
// already-enrolled nodes are unaffected.
async function showEnroll() {
  const { token, control_url: controlUrl } = await api('/admin/enroll-token');
  const env = [
    `CONTROL_URL=${controlUrl || location.origin}`,
    `ENROLL_TOKEN=${token}`,
  ].join('\n');
  const rotate = el('button', { class: 'danger', onclick: () =>
    confirmDialog('Regenerate the enroll token?',
      'The old token stops working for new nodes. Already-connected nodes are unaffected.',
      'Regenerate', async () => {
        await api('/admin/enroll-token/rotate', { method: 'POST' });
        showEnroll();
      }) }, 'Regenerate');
  const copy = el('button', { class: 'filled', onclick: () => {
    navigator.clipboard.writeText(env).then(() => toast('Copied'));
  } }, 'Copy .env');
  dialog('Node enroll token', [
    el('p', { class: 'muted' }, 'The point operator puts this into .env next to the compose file — nothing else. The node connects and determines its location by itself.'),
    el('div', { class: 'secret' }, env),
  ], [rotate, copy]);
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
