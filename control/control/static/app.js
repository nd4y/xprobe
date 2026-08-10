'use strict';
// Probe control-plane UI. All target-set and provisioning logic lives in the
// backend; this only renders state and collects form input.

const MODES = ['tcp', 'status', 'download'];
const MODE_HINT = {
  tcp: 'connect + TLS to the inbound',
  status: 'HTTP request through the config',
  download: 'file download (bandwidth)',
};

let HOSTS = [];   // [{remark, inbound, disabled}]

function el(tag, attrs = {}, kids = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'onclick') n.onclick = v;
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
  setTimeout(() => { t.hidden = true; }, 2600);
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

function pill(on, text) {
  return el('span', { class: `pill ${on ? 'on' : 'off'}` }, text);
}

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
  who.replaceChildren(
    el('span', { class: 'muted' }, me.name || ''),
    ' ',
    el('a', { href: '/auth/logout', class: 'muted' }, 'sign out'),
  );
  await renderPoints();
}

async function renderPoints() {
  const box = document.getElementById('main');
  box.replaceChildren(el('div', { class: 'loader' }, 'loading…'));
  const [points, hosts] = await Promise.all([api('/admin/points'), api('/admin/panel/hosts')]);
  HOSTS = hosts;

  const head = el('div', { class: 'row' }, [
    el('h2', { class: 'grow' }, `Vantage points (${points.length})`),
    el('button', { class: 'small', onclick: showEnroll }, 'Enroll token'),
    el('button', { class: 'filled small', onclick: addPoint }, '+ Add point'),
  ]);
  const cards = points.map(pointCard);
  box.replaceChildren(el('div', { class: 'card' }, head), ...cards);
}

// Enroll token: a node registers with the control plane using it. One-time
// per node and rotatable — regenerating revokes the old token while
// already-enrolled nodes are unaffected.
async function showEnroll() {
  const { token, control_url: controlUrl } = await api('/admin/enroll-token');
  const compose = [
    `CONTROL_URL=${controlUrl || location.origin}`,
    `ENROLL_TOKEN=${token}`,
  ].join('\n');
  const rotate = el('button', { class: 'danger', onclick: async () => {
    if (!confirm('Regenerate the token? The old one will stop working for new nodes.')) return;
    await api('/admin/enroll-token/rotate', { method: 'POST' });
    document.getElementById('dialog').close();
    showEnroll();
  } }, 'Regenerate');
  const copy = el('button', { onclick: () => {
    navigator.clipboard.writeText(compose).then(() => toast('Copied'));
  } }, 'Copy .env');
  dialog('Node enroll token', [
    el('p', { class: 'muted' }, 'The point operator puts this into .env next to the compose file — nothing else. The node connects and determines its location by itself.'),
    el('div', { class: 'secret' }, compose),
    el('div', { class: 'row' }, [rotate]),
  ], [copy]);
}

function pointCard(p) {
  const modes = MODES.filter((m) => p.modes[m]).join(' · ') || '—';
  return el('div', { class: 'card' }, [
    el('div', { class: 'row' }, [
      el('div', { class: 'grow' }, [
        el('div', {}, [
          el('b', {}, p.name), ' ',
          el('span', { class: 'muted' }, [p.city, p.country].filter(Boolean).join(', ')),
        ]),
        el('div', { class: 'muted mono' }, `v${p.version} · ${modes} · ${p.vantage}`),
      ]),
      pill(p.enabled, p.enabled ? 'enabled' : 'disabled'),
      el('button', { class: 'small', onclick: () => editPoint(p.name) }, 'Configure'),
    ]),
  ]);
}

function hostChecklist(selected) {
  const sel = new Set(selected || []);
  const wrap = el('div', { class: 'checks' });
  for (const h of HOSTS) {
    const cb = el('input', { type: 'checkbox', checked: sel.has(h.remark) });
    cb.dataset.remark = h.remark;
    wrap.append(el('label', {}, [cb, el('span', {}, h.remark), el('span', { class: 'in' }, h.inbound)]));
  }
  return wrap;
}

function pickedRemarks(wrap) {
  return [...wrap.querySelectorAll('input:checked')].map((c) => c.dataset.remark);
}

async function editPoint(name) {
  const p = await api(`/admin/points/${encodeURIComponent(name)}`);

  const vantage = el('select', {}, [
    el('option', { value: 'home', ...(p.vantage === 'home' ? { selected: '' } : {}) }, 'home'),
    el('option', { value: 'node', ...(p.vantage === 'node' ? { selected: '' } : {}) }, 'node'),
  ]);
  const country = el('input', { value: p.country || '' });
  const city = el('input', { value: p.city || '' });
  const isp = el('input', { value: p.isp || '', placeholder: 'optional' });
  const enabled = el('input', { type: 'checkbox', checked: p.enabled });
  // Per check: enabled or not and how often (seconds), individually.
  const DEF_INT = { tcp: 120, status: 900, download: 1800 };
  const modeBoxes = {};
  const intBoxes = {};
  const modesRow = el('div', { class: 'grid' }, MODES.map((m) => {
    const cb = el('input', { type: 'checkbox', checked: !!p.modes[m] });
    const iv = el('input', { type: 'number', min: '10', step: '10',
      value: String((p.intervals && p.intervals[m]) || DEF_INT[m]) });
    modeBoxes[m] = cb; intBoxes[m] = iv;
    return el('label', { class: 'field', title: MODE_HINT[m] }, [
      el('span', {}, `${m} — ${MODE_HINT[m]}`),
      el('div', { class: 'row' }, [cb, el('span', { class: 'muted' }, 'every'), iv,
        el('span', { class: 'muted' }, 'sec')]),
    ]);
  }));

  const pinGeo = el('input', { type: 'checkbox', checked: p.pin_geo });
  const geoNote = el('div', { class: 'muted' },
    p.pin_geo ? 'Geo is pinned manually.'
              : `Detected by the probe: ${[p.city, p.isp].filter(Boolean).join(', ') || '—'}`);

  const check = hostChecklist(p.check_remarks);
  const load = hostChecklist(p.load_remarks);

  const save = el('button', { class: 'filled', onclick: async (e) => {
    e.target.disabled = true;
    try {
      await api(`/admin/points/${encodeURIComponent(name)}`, {
        method: 'PATCH',
        body: {
          vantage: vantage.value, country: country.value, city: city.value, isp: isp.value,
          pin_geo: pinGeo.checked, enabled: enabled.checked,
          modes: Object.fromEntries(MODES.map((m) => [m, modeBoxes[m].checked])),
          intervals: Object.fromEntries(MODES.map((m) => [m, Number(intBoxes[m].value) || 0])),
        },
      });
      await api(`/admin/points/${encodeURIComponent(name)}/set`, {
        method: 'POST',
        body: { check_remarks: pickedRemarks(check), load_remarks: pickedRemarks(load) },
      });
      toast('Saved, version bumped');
      document.getElementById('dialog').close();
      await renderPoints();
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Save');

  const rotate = el('button', { class: 'small', onclick: async () => {
    const r = await api(`/admin/points/${encodeURIComponent(name)}/rotate-secret`, { method: 'POST' });
    showSecret('New secret', r.secret, name);
  } }, 'Rotate secret');

  const del = el('button', { class: 'small danger', onclick: async () => {
    if (!confirm(`Remove point ${name} from the control plane? Panel accounts and squads will remain.`)) return;
    await api(`/admin/points/${encodeURIComponent(name)}`, { method: 'DELETE' });
    toast('Removed'); document.getElementById('dialog').close(); await renderPoints();
  } }, 'Remove');

  dialog(`Point ${name}`, [
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'vantage'), vantage]),
      el('label', { class: 'field' }, [el('span', {}, 'country'), country]),
      el('label', { class: 'field' }, [el('span', {}, 'city'), city]),
      el('label', { class: 'field' }, [el('span', {}, 'network (isp)'), isp]),
    ]),
    el('label', { class: 'field' }, [el('span', {}, 'enabled'), enabled]),
    el('label', { class: 'field' }, [el('span', {}, 'pin geo manually'), pinGeo]),
    geoNote,
    el('div', { class: 'muted' }, 'Checks and intervals:'), modesRow,
    el('div', { class: 'muted' }, 'Frequent checks (tcp/status) — targets:'), check,
    el('div', { class: 'muted' }, 'Bandwidth check (download) — targets:'), load,
    el('div', { class: 'row' }, [rotate, del]),
  ], [save]);
}

async function addPoint() {
  const name = el('input', { placeholder: 'e.g. yaroslavl' });
  const country = el('input', { value: 'RU' });
  const city = el('input', {});
  const vantage = el('select', {}, [
    el('option', { value: 'home' }, 'home'), el('option', { value: 'node' }, 'node'),
  ]);
  const check = hostChecklist([]);
  const load = hostChecklist([]);

  const create = el('button', { class: 'filled', onclick: async (e) => {
    e.target.disabled = true;
    try {
      const r = await api('/admin/points', {
        method: 'POST',
        body: {
          name: name.value.trim(), country: country.value, city: city.value, vantage: vantage.value,
          check_remarks: pickedRemarks(check), load_remarks: pickedRemarks(load),
        },
      });
      showSecret('Point provisioned', r.secret, r.name, r.install);
      await renderPoints();
    } catch (err) { toast(String(err.message)); e.target.disabled = false; }
  } }, 'Provision');

  dialog('New point', [
    el('div', { class: 'grid' }, [
      el('label', { class: 'field' }, [el('span', {}, 'name'), name]),
      el('label', { class: 'field' }, [el('span', {}, 'country'), country]),
      el('label', { class: 'field' }, [el('span', {}, 'city'), city]),
      el('label', { class: 'field' }, [el('span', {}, 'vantage'), vantage]),
    ]),
    el('div', { class: 'muted' }, 'Frequent checks (tcp/status) — targets:'), check,
    el('div', { class: 'muted' }, 'Bandwidth check (download) — targets:'), load,
  ], [create]);
}

function showSecret(title, secret, name, install) {
  const body = [
    el('p', { class: 'muted' }, 'The secret is shown only once — save it.'),
    el('div', { class: 'secret' }, secret),
  ];
  if (install) {
    body.push(el('p', { class: 'muted' }, 'Install command for the point operator:'));
    body.push(el('div', { class: 'secret' }, install));
  }
  const copy = el('button', { onclick: () => {
    navigator.clipboard.writeText(install || secret).then(() => toast('Copied'));
  } }, 'Copy');
  dialog(title, body, [copy]);
}

main().catch((e) => {
  document.getElementById('main').replaceChildren(el('div', { class: 'signin' }, String(e.message)));
});
