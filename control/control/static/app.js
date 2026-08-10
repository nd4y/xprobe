'use strict';
// Probe control-plane UI. All target-set and provisioning logic lives in the
// backend; this renders state and collects form input.
//
// Views (hash routed): #/ — the point list, #/p/<name> — one point's page.
// A full page instead of a dialog: the target table is large, and nesting it
// into a modal produced scroll-in-scroll.

const MODES = ['tcp', 'status', 'download'];
const MODE_HINT = {
  tcp: 'connect + TLS handshake to the inbound',
  status: 'HTTP request through the config',
  download: 'file download, measures bandwidth',
};
const DEF_INT = { tcp: 120, status: 900, download: 1800 };

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

// ── routing ──────────────────────────────────────────────────────────────────

async function route() {
  const m = location.hash.match(/^#\/p\/(.+)$/);
  try {
    if (m) await pointView(decodeURIComponent(m[1]));
    else await listView();
  } catch (e) {
    document.getElementById('main').replaceChildren(
      el('div', { class: 'signin' }, String(e.message)));
  }
}
window.addEventListener('hashchange', route);

async function main() {
  const me = await api('/me').catch(() => ({ authenticated: false }));
  const who = document.getElementById('who');
  const box = document.getElementById('main');
  if (!me.authenticated || !me.owner) {
    who.replaceChildren();
    box.replaceChildren(el('div', { class: 'signin' }, [
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
  const box = document.getElementById('main');
  box.replaceChildren(el('div', { class: 'loader' }, 'loading…'));
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
        ...modes.map((m) => chip(`${m} / ${(p.intervals && p.intervals[m]) || DEF_INT[m]}s`)),
      ]),
    ]);
  });

  box.replaceChildren(toolbar, el('div', { class: 'points' },
    cards.length ? cards : [el('div', { class: 'muted' }, 'No points yet — add one or share the enroll token.')]));
}

// ── point view ───────────────────────────────────────────────────────────────

async function pointView(name) {
  const box = document.getElementById('main');
  box.replaceChildren(el('div', { class: 'loader' }, 'loading…'));
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
  const checksCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Checks'),
      el('div', { class: 'muted' }, 'Each check runs on its own schedule.'),
    ]),
    ...MODES.map((m) => {
      const sw = mswitch(!!p.modes[m]);
      const iv = el('input', { type: 'number', min: '10', step: '10',
        value: String((p.intervals && p.intervals[m]) || DEF_INT[m]) });
      modeBoxes[m] = sw.input; intBoxes[m] = iv;
      return el('div', { class: 'check-row' }, [
        sw,
        el('span', { class: 'name' }, m),
        el('span', { class: 'muted grow' }, MODE_HINT[m]),
        el('span', { class: 'every' }, [el('span', { class: 'muted' }, 'every'), iv,
          el('span', { class: 'muted' }, 's')]),
      ]);
    }),
  ]);

  // — targets: one table, two checkbox columns —
  const checkSel = new Set(p.check_remarks || []);
  const loadSel = new Set(p.load_remarks || []);
  const search = el('input', { type: 'search', placeholder: 'Filter hosts…' });
  const tbody = el('tbody');
  const allCheck = el('input', { type: 'checkbox', title: 'toggle all visible' });
  const allLoad = el('input', { type: 'checkbox', title: 'toggle all visible' });

  function visibleHosts() {
    const q = search.value.trim().toLowerCase();
    return hosts.filter((h) =>
      !q || h.remark.toLowerCase().includes(q) || h.inbound.toLowerCase().includes(q));
  }
  function renderRows() {
    const vis = visibleHosts();
    tbody.replaceChildren(...vis.map((h) => {
      const cb = el('input', { type: 'checkbox', checked: checkSel.has(h.remark),
        onchange: (e) => { e.target.checked ? checkSel.add(h.remark) : checkSel.delete(h.remark); syncAll(); } });
      const lb = el('input', { type: 'checkbox', checked: loadSel.has(h.remark),
        onchange: (e) => { e.target.checked ? loadSel.add(h.remark) : loadSel.delete(h.remark); syncAll(); } });
      return el('tr', {}, [
        el('td', {}, [h.remark, el('span', { class: 'in' }, h.inbound)]),
        el('td', { class: 'c' }, cb),
        el('td', { class: 'c' }, lb),
      ]);
    }));
    syncAll();
  }
  function syncAll() {
    const vis = visibleHosts();
    allCheck.checked = vis.length > 0 && vis.every((h) => checkSel.has(h.remark));
    allLoad.checked = vis.length > 0 && vis.every((h) => loadSel.has(h.remark));
  }
  allCheck.onchange = () => {
    visibleHosts().forEach((h) => allCheck.checked ? checkSel.add(h.remark) : checkSel.delete(h.remark));
    renderRows();
  };
  allLoad.onchange = () => {
    visibleHosts().forEach((h) => allLoad.checked ? loadSel.add(h.remark) : loadSel.delete(h.remark));
    renderRows();
  };
  search.oninput = renderRows;
  renderRows();

  const targetsCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Targets'),
      el('div', { class: 'muted' },
        'Frequent = tcp + status (cheap, the full set). Bandwidth = download (heavy — keep this set short).'),
    ]),
    el('div', { class: 'targets-tools' }, [search]),
    el('div', { class: 'targets' }, el('div', { class: 'scroll' },
      el('table', {}, [
        el('thead', {}, el('tr', {}, [
          el('th', {}, 'Host'),
          el('th', { class: 'c' }, ['Frequent ', allCheck]),
          el('th', { class: 'c' }, ['Bandwidth ', allLoad]),
        ])),
        tbody,
      ]))),
  ]);

  // — maintenance —
  const maintCard = el('div', { class: 'card' }, [
    el('div', { class: 'section-title' }, [
      el('h3', {}, 'Maintenance'),
      el('div', { class: 'muted' }, 'Rotating the secret restarts the probe; removal only forgets the point here — panel accounts and squads remain.'),
    ]),
    el('div', { class: 'row' }, [
      el('button', { class: 'outlined', onclick: async () => {
        const r = await api(`/admin/points/${encodeURIComponent(name)}/rotate-secret`, { method: 'POST' });
        showSecret('New secret', r.secret);
      } }, 'Rotate secret'),
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
        },
      });
      await api(`/admin/points/${encodeURIComponent(name)}/set`, {
        method: 'POST',
        body: { check_remarks: [...checkSel], load_remarks: [...loadSel] },
      });
      toast('Saved — the probe restarts with the new version');
      await pointView(name);
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Save changes');
  const savebar = el('div', { class: 'savebar' }, el('div', { class: 'inner' }, [
    el('span', { class: 'muted grow' }, 'Saving bumps the document version; the probe picks it up within a minute.'),
    save,
  ]));

  box.replaceChildren(head, el('div', { class: 'stack' },
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
      showSecret('Point provisioned', r.secret, r.install,
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

function showSecret(title, secret, install, onClose) {
  const d = document.getElementById('dialog');
  const body = [
    el('p', { class: 'muted' }, 'The secret is shown only once — save it.'),
    el('div', { class: 'secret' }, secret),
  ];
  if (install) {
    body.push(el('p', { class: 'muted' }, 'Install command for the point operator:'));
    body.push(el('div', { class: 'secret' }, install));
  }
  const copy = el('button', { class: 'filled', onclick: () => {
    navigator.clipboard.writeText(install || secret).then(() => toast('Copied'));
  } }, 'Copy');
  dialog(title, body, [copy]);
  if (onClose) d.addEventListener('close', onClose, { once: true });
}

main().catch((e) => {
  document.getElementById('main').replaceChildren(
    el('div', { class: 'signin' }, String(e.message)));
});
