#!/usr/bin/env node
// Fills a fresh SPA with demo data through its real HTTP API: the first administrator changes the initial
// password, then people, groups (local and directory), the four Umbrella applications with their access rules,
// the password policy and the general settings.
//
//   SPA_URL=http://localhost:8080 SPA_ADMIN_PASSWORD=<initial> SPA_DEMO_PASSWORD=<new> node scripts/seed-demo.mjs
//
// Running it again is harmless: what exists is left as it is.

const BASE = process.env.SPA_URL ?? 'http://localhost:8080';
const ADMIN = process.env.SPA_ADMIN_USERNAME ?? 'admin';
const INITIAL = process.env.SPA_ADMIN_PASSWORD ?? '';
export const DEMO_PASSWORD = process.env.SPA_DEMO_PASSWORD ?? 'Umbrella-Admin-2026!';
const USER_PASSWORD = 'Welcome-to-Umbrella-1';

export class Client {
  constructor(base = BASE) {
    this.base = base;
    this.cookies = new Map();
  }
  async call(method, path, body) {
    const headers = { Accept: 'application/json', Origin: this.base };
    if (method !== 'GET') headers['X-Requested-With'] = 'spa';
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.cookies.size) headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(this.base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      this.cookies.set(kv.slice(0, i), kv.slice(i + 1));
    }
    const text = await res.text();
    const data = text ? JSON.parse(text) : undefined;
    if (!res.ok) {
      const err = new Error(`${method} ${path}: ${res.status} ${data?.message ?? text}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }
  get(p) {
    return this.call('GET', p);
  }
  post(p, b = {}) {
    return this.call('POST', p, b);
  }
  put(p, b) {
    return this.call('PUT', p, b);
  }
}

/** Signs the administrator in, changing the initial password on the first run. */
export async function signInAdmin(c) {
  try {
    await c.post('/api/v1/auth/password', { username: ADMIN, password: DEMO_PASSWORD });
    return;
  } catch (e) {
    if (!INITIAL) throw e;
  }
  try {
    await c.post('/api/v1/auth/password', { username: ADMIN, password: INITIAL });
  } catch (e) {
    if (e.data?.code !== 'password_change_required') throw e;
    await c.post('/api/v1/auth/password/change', { ticket: e.data.extra.ticket, current: INITIAL, new: DEMO_PASSWORD });
  }
}

const PEOPLE = [
  { username: 'jdoe', name: 'John Doe', email: 'john.doe@umbrella.example', spa_role: 'user', groups: ['NOC'] },
  { username: 'asmith', name: 'Alice Smith', email: 'alice.smith@umbrella.example', spa_role: 'auditor', groups: ['Security'] },
  { username: 'mpetrova', name: 'Maria Petrova', email: 'maria.petrova@umbrella.example', spa_role: 'admin', groups: ['Platform team'] },
  { username: 'ivolkov', name: 'Ivan Volkov', email: 'ivan.volkov@umbrella.example', spa_role: 'user', groups: ['Network engineers', 'NOC'] },
  { username: 'kchen', name: 'Kevin Chen', email: 'kevin.chen@umbrella.example', spa_role: 'user', groups: ['Platform team'] },
  { username: 'lgarcia', name: 'Lucia Garcia', email: 'lucia.garcia@umbrella.example', spa_role: 'user', groups: ['Network engineers'] },
  { username: 'onovak', name: 'Oleg Novak', email: 'oleg.novak@umbrella.example', spa_role: 'user', groups: ['NOC'], disabled: true },
];

const GROUPS = [
  { name: 'NOC', description: 'Network operations centre, 24/7 on-call' },
  { name: 'Platform team', description: 'Runs the Umbrella platform' },
  { name: 'Network engineers', description: 'Routers, switches and firewalls' },
  { name: 'Security', description: 'Information security and audit' },
  { name: 'Domain Admins', description: 'From Active Directory', source: 'ldap', external_id: 'CN=Domain Admins,CN=Users,DC=umbrella,DC=example' },
  { name: 'Umbrella Operators (Entra)', description: 'From Microsoft Entra ID', source: 'entra', external_id: '6f1c2a9e-3b7d-4e21-9a0c-5d8e7f6a1b2c' },
];

const APPS = [
  { type: 'umbrella-monitoring', name: 'Umbrella Monitoring', base_url: 'https://monitoring.umbrella.example', rules: [['Platform team', 'admin'], ['NOC', 'user'], ['Security', 'user']] },
  { type: 'umbrella-flow', name: 'Umbrella Flow', base_url: 'https://flow.umbrella.example', rules: [['Platform team', 'admin']] },
  { type: 'inventory-db', name: 'Inventory DB', base_url: 'https://inventory.umbrella.example', rules: [['Platform team', 'admin'], ['Network engineers', 'editor'], ['NOC', 'viewer'], ['Domain Admins', 'admin']] },
  { type: 'network-control', name: 'Network Control', base_url: 'https://netctl.umbrella.example', rules: [['Network engineers', 'operator'], ['NOC', 'viewer'], ['Umbrella Operators (Entra)', 'operator']] },
];

export async function seed(c = new Client()) {
  await signInAdmin(c);
  const general = await c.get('/api/v1/settings/general');
  await c.put('/api/v1/settings/general', { general: { ...general.general, organization: 'Umbrella Corporation' }, passkeys: general.passkeys });
  await c.put('/api/v1/settings/password-policy', {
    min_length: 12, require_digits: true, min_digits: 1, require_special: true, min_special: 1, require_mixed_case: true,
    letters: 'latin', max_age_days: 180, warn_days: 14, history_count: 5, block_common: true, lockout_attempts: 5, lockout_minutes: 15,
  });

  // Directories and providers (the demo servers do not exist: sign-in through them fails, the pages show them)
  await c.put('/api/v1/settings/ldap', {
    config: { enabled: true, kind: 'ad', url: 'ldaps://dc1.umbrella.example:636', bind_dn: 'CN=svc-spa,OU=Service Accounts,DC=umbrella,DC=example',
      base_dn: 'DC=umbrella,DC=example', admin_group_dn: 'CN=SPA Admins,OU=Groups,DC=umbrella,DC=example' },
    bind_password: 'demo-bind-password',
  });
  await c.put('/api/v1/settings/entra', {
    config: { enabled: true, cloud: 'global', tenant_id: 'umbrella.onmicrosoft.com', client_id: '3f2b6c1e-8d4a-4b7e-9c2f-1a5d7e9b0c3d', user_group_id: '6f1c2a9e-3b7d-4e21-9a0c-5d8e7f6a1b2c' },
    client_secret: 'demo-client-secret',
  });
  // Google needs its discovery document: skipped when SPA cannot reach accounts.google.com.
  await c.put('/api/v1/settings/providers/google', {
    config: { enabled: true, client_id: '123456789012-demo.apps.googleusercontent.com', allowed_domains: ['umbrella.example'], existing_only: true },
    client_secret: 'demo-google-secret',
  }).catch((e) => console.warn(`Google provider not enabled: ${e.message}`));

  let groups = await c.get('/api/v1/groups');
  for (const g of GROUPS) if (!groups.some((x) => x.name === g.name)) await c.post('/api/v1/groups', g);
  groups = await c.get('/api/v1/groups');
  const gid = (name) => groups.find((g) => g.name === name).id;

  let users = await c.get('/api/v1/users');
  for (const p of PEOPLE) {
    if (users.some((u) => u.username === p.username)) continue;
    const u = await c.post('/api/v1/users', { ...p, disabled: false, password: USER_PASSWORD, groups: p.groups.map(gid) });
    if (p.disabled) await c.put(`/api/v1/users/${u.id}`, { ...p, disabled: true, groups: p.groups.map(gid) });
  }
  users = await c.get('/api/v1/users');
  const me = users.find((u) => u.username === ADMIN);
  await c.put(`/api/v1/users/${me.id}`, { username: ADMIN, name: 'Sam Carter', email: 'sam.carter@umbrella.example', spa_role: 'admin', disabled: false, groups: [gid('Platform team'), gid('NOC')] });

  const { applications } = await c.get('/api/v1/applications');
  const keys = {};
  for (const a of APPS) {
    if (applications.some((x) => x.name === a.name)) continue;
    const conn = await c.post('/api/v1/applications', {
      type: a.type, name: a.name, base_url: a.base_url,
      assignments: a.rules.map(([g, role]) => ({ subject_type: 'group', subject_id: gid(g), role })),
    });
    keys[a.name] = conn.key;
  }
  // Umbrella Monitoring connects: it publishes its role catalogue and reads its people (the federation API).
  if (keys['Umbrella Monitoring']) {
    const { token } = JSON.parse(Buffer.from(keys['Umbrella Monitoring'].slice(5), 'base64url').toString());
    const fed = (method, path, body) =>
      fetch(c.base + path, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) }).then((r) => r.json());
    await fed('PUT', '/api/spa/v1/roles', {
      roles: [
        { id: 'admin', name: 'Administrator', description: 'Everything, including settings' },
        { id: 'user', name: 'User', description: 'Incidents, on-call and the catalogue' },
        { id: 'noc-lead', name: 'NOC lead', description: 'Manages on-call schedules' },
      ],
      default: 'user',
    });
    await fed('GET', '/api/spa/v1/users');
  }
  // A failed sign-in, so that the audit log shows one.
  await new Client(c.base).post('/api/v1/auth/password', { username: 'jdoe', password: 'wrong-password' }).catch(() => undefined);
  return { keys };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  seed()
    .then(({ keys }) => {
      console.log(`SPA at ${BASE} is ready. Sign in as ${ADMIN} / ${DEMO_PASSWORD}`);
      for (const [name, key] of Object.entries(keys)) console.log(`${name}: SPA_CONNECTION_KEY=${key}`);
    })
    .catch((e) => {
      console.error(e.message);
      process.exit(1);
    });
}
