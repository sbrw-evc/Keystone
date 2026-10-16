#!/usr/bin/env node
// End-to-end check of a live Keystone with a real application, Beacon (docs/e2e.md):
//
//   1. builds Keystone and starts it on a free port with a fresh database;
//   2. takes a snapshot of the Beacon repository (git archive, nothing there is changed), builds its web
//      UI and its server as a test binary (scripts/e2e/beacon_serve_test.go: the app as cmd/beacon runs it after
//      the setup wizard, with PostgreSQL and the fake OpenBao of Beacon's own tests);
//   3. drives the real flow in Chromium (Playwright): the administrator connects Beacon in Keystone's wizard
//      and gives alice its admin role and bob its user role; the password policy requires a second factor; Beacon
//      starts with the connection key and publishes its role catalogue; alice and bob open Beacon, are sent to Keystone,
//      change their first password, set up the authenticator app and come back signed in; Beacon has both people
//      with their roles; Keystone disables bob; after "Synchronize now" in Beacon bob is locked there, his session is
//      gone and Keystone refuses his next sign-in.
//
//   make e2e-beacon            (or: node scripts/e2e-beacon.mjs)
//
// Environment (all optional):
//   E2E_POSTGRES              PostgreSQL server URL (default postgres://postgres:postgres@127.0.0.1:55432); the
//                             databases spa_e2e and um_e2e are dropped and created again
//   BEACON_DIR                the Beacon repository (default ../beacon next to Keystone, else ../Umbrella-Monitoring,
//                             its name before the rename; UMBRELLA_MONITORING_DIR is still read)
//   BEACON_REF                the commit to check (default HEAD; UMBRELLA_MONITORING_REF is still read)
//   UM_WEB_DIST               a built web UI of Beacon to use instead of building the snapshot's
//   E2E_WORK                  working directory (default a new one under the system temp directory)
//   E2E_KEEP=1                keep Keystone and Beacon running at the end (Ctrl+C stops them)
//   CHROMIUM                  the browser binary (default the newest chromium-* under PLAYWRIGHT_BROWSERS_PATH)
//
// Needs Go, Node with Playwright (project or global), psql and git.
import { execFileSync, execSync, spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PG = (process.env.E2E_POSTGRES ?? 'postgres://postgres:postgres@127.0.0.1:55432').replace(/\/+$/, '');
const UM_REPO = resolve(process.env.BEACON_DIR ?? process.env.UMBRELLA_MONITORING_DIR
  ?? (existsSync(join(ROOT, '..', 'beacon')) ? join(ROOT, '..', 'beacon') : join(ROOT, '..', 'Umbrella-Monitoring')));
const UM_REF = process.env.BEACON_REF ?? process.env.UMBRELLA_MONITORING_REF ?? 'HEAD';
const WORK = process.env.E2E_WORK ? resolve(process.env.E2E_WORK) : mkdtempSync(join(tmpdir(), 'keystone-e2e-'));
mkdirSync(WORK, { recursive: true });

const ADMIN_INITIAL = 'Initial-Passw0rd!';
const ADMIN_PASSWORD = 'Admin-Secret-2026!';
const PEOPLE = {
  alice: { name: 'Alice Admin', email: 'alice@umbrella.example', initial: 'Alice-Initial-1!', password: 'Alice-Secret-2026!', role: 'admin' },
  bob: { name: 'Bob User', email: 'bob@umbrella.example', initial: 'Bob-Initial-1!', password: 'Bob-Secret-2026!', role: 'user' },
};

// ---- output

const results = [];
function step(text) {
  console.log(`\n== ${text}`);
}
function check(ok, text, detail = '') {
  results.push({ ok, text });
  console.log(`${ok ? '  ok  ' : '  FAIL'} ${text}${detail ? ` — ${detail}` : ''}`);
  if (!ok) throw new Error(`check failed: ${text}${detail ? ` (${detail})` : ''}`);
}
function run(cmd, args, opts = {}) {
  console.log(`  $ ${cmd} ${args.join(' ')}${opts.cwd ? `   (in ${opts.cwd})` : ''}`);
  execFileSync(cmd, args, { stdio: ['ignore', 'inherit', 'inherit'], ...opts });
}

// ---- helpers

function freePort() {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once('error', fail);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => ok(port));
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(what, fn, timeout = 30000, every = 250) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await sleep(every);
  }
  throw new Error(`timed out waiting for ${what}${last ? `: ${last.message}` : ''}`);
}

/** RFC 6238 code of a base32 secret (what an authenticator app shows). */
function totp(secret, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac('sha1', key).update(counter).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}

function psql(db, sql) {
  execFileSync('psql', [`${PG}/${db}`, '-v', 'ON_ERROR_STOP=1', '-qc', sql], { stdio: ['ignore', 'ignore', 'inherit'] });
}

function pgParts() {
  const u = new URL(PG);
  return { host: u.hostname, port: u.port || '5432', user: decodeURIComponent(u.username), password: decodeURIComponent(u.password) };
}

async function loadPlaywright() {
  try {
    return await import('playwright');
  } catch {
    const root = execSync('npm root -g').toString().trim();
    return import(join(root, 'playwright', 'index.mjs'));
  }
}

function chromiumPath() {
  if (process.env.CHROMIUM) return process.env.CHROMIUM;
  const dir = process.env.PLAYWRIGHT_BROWSERS_PATH ?? '/opt/pw-browsers';
  if (!existsSync(dir)) return undefined;
  for (const d of readdirSync(dir).filter((n) => /^chromium-\d+$/.test(n)).sort().reverse()) {
    const bin = join(dir, d, 'chrome-linux', 'chrome');
    if (existsSync(bin)) return bin;
  }
  return undefined;
}

const children = [];
function start(name, cmd, args, env, ready) {
  const log = [];
  const p = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(p);
  let readyResolve;
  const isReady = new Promise((r) => (readyResolve = r));
  const onData = (b) => {
    const s = b.toString();
    log.push(s);
    if (ready && s.includes(ready)) readyResolve();
  };
  p.stdout.on('data', onData);
  p.stderr.on('data', onData);
  p.on('exit', (code) => {
    if (code && code !== 0) console.log(`  ${name} exited with ${code}`);
  });
  p.logText = () => log.join('');
  p.ready = isReady;
  return p;
}

function stopAll() {
  for (const p of children) if (p.exitCode === null) p.kill('SIGTERM');
}
process.on('SIGINT', () => {
  stopAll();
  process.exit(130);
});

/** JSON of a page's API call with the page's cookies. */
async function api(page, method, url, body, headers = {}) {
  const res = await page.request.fetch(url, {
    method,
    data: body === undefined ? undefined : JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', ...headers },
    failOnStatusCode: false,
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = text;
  }
  return { status: res.status(), data };
}

// ---- main

let spaURL, umURL;
async function main() {
  console.log(`Keystone ${ROOT}\nBeacon ${UM_REPO} @ ${UM_REF}\nwork ${WORK}`);

  step('Build Keystone');
  if (!existsSync(join(ROOT, 'web', 'dist', 'index.html'))) {
    if (!existsSync(join(ROOT, 'web', 'node_modules'))) run('npm', ['ci', '--no-audit', '--no-fund'], { cwd: join(ROOT, 'web') });
    run('npm', ['run', 'build'], { cwd: join(ROOT, 'web') });
  }
  run('go', ['build', '-o', join(WORK, 'keystone'), './cmd/keystone'], { cwd: join(ROOT, 'backend') });

  step('Snapshot and build Beacon');
  const umCommit = execFileSync('git', ['-C', UM_REPO, 'rev-parse', UM_REF]).toString().trim();
  const umBranch = execFileSync('git', ['-C', UM_REPO, 'rev-parse', '--abbrev-ref', 'HEAD']).toString().trim();
  console.log(`  commit ${umCommit} (${umBranch})`);
  const snap = join(WORK, 'beacon');
  rmSync(snap, { recursive: true, force: true });
  mkdirSync(snap, { recursive: true });
  execSync(`git -C '${UM_REPO}' archive '${umCommit}' app | tar -x -C '${snap}'`);
  const runnerDir = join(snap, 'app', 'backend', 'cmd', 'keystone-e2e');
  mkdirSync(runnerDir, { recursive: true });
  cpSync(join(ROOT, 'scripts', 'e2e', 'beacon_serve_test.go'), join(runnerDir, 'serve_test.go'));
  run('go', ['test', '-c', '-tags', 'keystonee2e', '-o', join(WORK, 'beacon-e2e.test'), './cmd/keystone-e2e'], { cwd: join(snap, 'app', 'backend') });
  let umWeb = process.env.UM_WEB_DIST ? resolve(process.env.UM_WEB_DIST) : '';
  if (!umWeb) {
    run('npm', ['ci', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: join(snap, 'app', 'web') });
    run('npm', ['run', 'build'], { cwd: join(snap, 'app', 'web') });
    umWeb = join(snap, 'app', 'web', 'dist');
  }

  step('Fresh databases spa_e2e and um_e2e');
  for (const db of ['spa_e2e', 'um_e2e']) {
    psql('postgres', `DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    psql('postgres', `CREATE DATABASE ${db}`);
  }

  // Two different hosts, as two real deployments: Keystone on localhost, Beacon on 127.0.0.1.
  const spaPort = await freePort();
  const umPort = await freePort();
  spaURL = `http://localhost:${spaPort}`;
  umURL = `http://127.0.0.1:${umPort}`;

  step(`Start Keystone on ${spaURL}`);
  const spa = start('Keystone', join(WORK, 'keystone'), [], {
    SPA_DATABASE_URL: `${PG}/spa_e2e?sslmode=disable`,
    SPA_MASTER_KEY: Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))).toString('base64'),
    SPA_ADMIN_PASSWORD: ADMIN_INITIAL,
    SPA_LISTEN: `127.0.0.1:${spaPort}`,
    SPA_PUBLIC_URL: spaURL,
    SPA_WEB_DIR: join(ROOT, 'web', 'dist'),
  });
  await until('Keystone /healthz', async () => (await fetch(`${spaURL}/healthz`)).ok);
  check(true, 'Keystone answers /healthz');

  const { chromium } = await loadPlaywright();
  const browser = await chromium.launch({ executablePath: chromiumPath() });
  const context = async () => {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-GB' });
    await ctx.addInitScript(() => {
      localStorage.setItem('lang', 'en');
      localStorage.setItem('umbrella.locale', 'en');
    });
    return ctx;
  };
  const shots = join(WORK, 'screens');
  mkdirSync(shots, { recursive: true });

  try {
    step('Keystone administrator: first sign-in, people, password policy');
    const adminCtx = await context();
    const admin = await adminCtx.newPage();
    await admin.goto(`${spaURL}/signin`);
    await admin.getByLabel('User name').fill('admin');
    await admin.locator('input[type=password]').fill(ADMIN_INITIAL);
    await admin.getByRole('button', { name: 'Sign in', exact: true }).click();
    await admin.getByText('Choose a new password').waitFor();
    const pw = admin.locator('input[type=password]');
    await pw.nth(0).fill(ADMIN_INITIAL);
    await pw.nth(1).fill(ADMIN_PASSWORD);
    await pw.nth(2).fill(ADMIN_PASSWORD);
    await admin.getByRole('button', { name: 'Change password and sign in' }).click();
    await admin.waitForURL(`${spaURL}/`);
    check(true, 'the administrator changed the initial password and is signed in to Keystone');

    const spaApi = (method, path, body) => api(admin, method, spaURL + path, body, { 'X-Requested-With': 'spa' });
    const ids = {};
    for (const [username, p] of Object.entries(PEOPLE)) {
      const r = await spaApi('POST', '/api/v1/users', { username, name: p.name, email: p.email, password: p.initial, spa_role: 'user' });
      check(r.status === 201, `Keystone created ${username}`, `HTTP ${r.status}`);
      ids[username] = r.data.id;
    }

    await admin.goto(`${spaURL}/settings/password-policy`);
    await admin.getByRole('radio', { name: 'Required for everyone' }).click();
    await admin.getByRole('button', { name: 'Save', exact: true }).click();
    await admin.getByText('The password policy is saved').waitFor();
    const pol = await spaApi('GET', '/api/v1/settings/password-policy');
    check(pol.data?.policy?.second_factor === 'everyone', 'the password policy requires a second factor of everyone');

    step('Keystone administrator: connect Beacon (wizard), alice → admin, bob → user');
    await admin.goto(`${spaURL}/applications?connect=1`);
    await admin.locator('.type-option', { hasText: 'Beacon' }).click();
    await admin.getByLabel('Name', { exact: true }).fill('Beacon');
    await admin.getByLabel('Address', { exact: true }).fill(umURL);
    await admin.getByRole('button', { name: 'Next', exact: true }).click();
    for (const [i, [username, p]] of Object.entries(PEOPLE).entries()) {
      await admin.getByRole('button', { name: 'Add a rule' }).click();
      const row = admin.locator('.rule-row').nth(i);
      await row.locator('select').nth(0).selectOption('user');
      await row.locator('select').nth(1).selectOption(ids[username]);
      await row.locator('select').nth(2).selectOption(p.role);
    }
    await admin.screenshot({ path: join(shots, '1-keystone-wizard-access.png') });
    await admin.getByRole('button', { name: 'Connect', exact: true }).click();
    const keyBox = admin.locator('.key-box');
    await keyBox.waitFor();
    const key = (await keyBox.textContent()).trim();
    check(key.startsWith('spa1.'), 'Keystone showed the connection key once', `${key.slice(0, 12)}…`);
    await admin.screenshot({ path: join(shots, '2-keystone-wizard-key.png') });
    await admin.getByRole('button', { name: 'Done', exact: true }).click();
    let apps = (await spaApi('GET', '/api/v1/applications')).data.applications;
    const appId = apps[0].id;
    check(apps.length === 1 && apps[0].type === 'beacon' && apps[0].callback === `${umURL}/api/auth/spa/callback`, 'the application is registered with its redirect address', apps[0].callback);
    check(!apps[0].roles_published, 'before Beacon starts, Keystone has only the preset catalogue', apps[0].roles.map((r) => r.id).join(', '));

    step(`Start Beacon on ${umURL} with SPA_CONNECTION_KEY`);
    const pg = pgParts();
    const um = start('Beacon', join(WORK, 'beacon-e2e.test'), ['-test.run', 'TestServe', '-test.timeout', '0'], {
      UM_ADDR: `127.0.0.1:${umPort}`,
      UM_POSTGRES: `${pg.host}:${pg.port}:${pg.user}:${pg.password}:um_e2e`,
      UM_WEB_DIR: umWeb,
      SPA_CONNECTION_KEY: key,
      SPA_PUBLIC_URL: umURL,
    }, 'BEACON READY');
    await Promise.race([um.ready, sleep(60000).then(() => Promise.reject(new Error('Beacon did not start:\n' + um.logText())))]);
    const meta = await (await fetch(`${umURL}/api/auth/spa`)).json();
    check(meta.connected && meta.issuer === spaURL, 'Beacon is connected to Keystone', `issuer ${meta.issuer}`);

    step('Beacon publishes its role catalogue and synchronizes');
    const published = await until('the role catalogue in Keystone', async () => {
      const a = (await spaApi('GET', '/api/v1/applications')).data.applications.find((x) => x.id === appId);
      return a.roles_published && a.last_sync_at ? a : null;
    });
    const roleIds = published.roles.map((r) => r.id);
    check(roleIds.includes('admin') && roleIds.includes('user'), 'Keystone received the role catalogue of Beacon', roleIds.join(', '));
    check(roleIds.length > 2, 'the catalogue holds the custom (preset) roles of Beacon too', `${roleIds.length} roles`);
    check(!!published.last_sync_at, 'Beacon read its people from the federation API', `last sync ${published.last_sync_at}`);

    step('alice and bob sign in to Beacon through Keystone (first password change, authenticator app set-up)');
    const signedIn = {};
    for (const [username, p] of Object.entries(PEOPLE)) {
      const ctx = await context();
      const page = await ctx.newPage();
      await page.goto(`${umURL}/`);
      await page.waitForURL((u) => u.href.startsWith(`${spaURL}/signin`), { timeout: 20000 });
      check(new URL(page.url()).searchParams.get('request') !== null, `${username}: Beacon sent the browser to Keystone's sign-in with the request`);
      await page.getByText('Beacon asks you to sign in').waitFor();
      await page.getByLabel('User name').fill(username);
      await page.locator('input[type=password]').fill(p.initial);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await page.getByText('Choose a new password').waitFor();
      const f = page.locator('input[type=password]');
      await f.nth(0).fill(p.initial);
      await f.nth(1).fill(p.password);
      await f.nth(2).fill(p.password);
      await page.getByRole('button', { name: 'Change password and sign in' }).click();
      await page.getByText('Set up two-step verification').first().waitFor();
      const secret = (await page.locator('.totp-key').textContent()).replace(/\s/g, '');
      if (username === 'alice') await page.screenshot({ path: join(shots, '3-keystone-totp-setup.png') });
      await page.getByLabel('Code from the app').fill(totp(secret));
      await page.getByRole('button', { name: 'Turn on and sign in' }).click();
      await page.locator('.recovery-codes').waitFor();
      const codes = await page.locator('.recovery-codes li').count();
      check(codes === 10, `${username}: set up the authenticator app during the sign-in, 10 recovery codes shown`);
      await page.getByRole('button', { name: 'I have saved the codes, continue' }).click();
      await page.waitForURL((u) => u.href.startsWith(umURL), { timeout: 20000 });
      const me = await until(`${username} in Beacon`, async () => {
        const r = await api(page, 'GET', `${umURL}/api/auth/me`);
        return r.status === 200 ? r.data : null;
      });
      check(me.username === username && me.role === p.role && me.source === 'spa', `${username} is signed in to Beacon with the role ${p.role}`, `role ${me.role}, source ${me.source}`);
      await page.waitForLoadState('load');
      await sleep(1500); // Beacon keeps a live feed open, so the network is never idle
      await page.screenshot({ path: join(shots, `4-beacon-${username}.png`) });
      signedIn[username] = { ctx, page, me };
    }
    const alice = signedIn.alice.page;
    const bob = signedIn.bob.page;
    const umApi = (page, method, path, body, csrf) => api(page, method, umURL + path, body, csrf ? { 'X-CSRF-Token': csrf } : {});

    step('Beacon has the people of Keystone');
    let users = (await umApi(alice, 'GET', '/api/users')).data;
    const byName = (n) => users.find((u) => u.username === n);
    check(byName('alice')?.role === 'admin' && byName('bob')?.role === 'user', 'Beacon lists alice (admin) and bob (user)', users.map((u) => `${u.username}:${u.role}${u.disabled ? ':disabled' : ''}`).join(', '));
    check(byName('alice')?.source === 'spa' && byName('bob')?.source === 'spa', 'both records are bound to Keystone');
    const fedUsers = (await spaApi('GET', '/api/v1/applications')).data.applications.find((x) => x.id === appId).users;
    check(fedUsers === 2, 'Keystone counts two people with access to Beacon', `users ${fedUsers}`);

    step('Keystone disables bob; Beacon locks him after "Synchronize now"');
    const bobUser = (await spaApi('GET', '/api/v1/users')).data.find((u) => u.username === 'bob');
    const upd = await spaApi('PUT', `/api/v1/users/${bobUser.id}`, { username: 'bob', name: bobUser.name, email: bobUser.email, spa_role: bobUser.spa_role, disabled: true, groups: bobUser.groups });
    check(upd.status === 200 && upd.data.disabled, 'Keystone disabled bob', `HTTP ${upd.status}`);
    check((await umApi(bob, 'GET', '/api/auth/me')).status === 200, 'before the synchronization bob still has his Beacon session');

    await alice.goto(`${umURL}/settings/keystone`);
    const syncBtn = alice.getByRole('button', { name: 'Synchronize now' });
    await syncBtn.waitFor();
    const syncDone = alice.waitForResponse((r) => r.url().endsWith('/api/settings/spa/sync') && r.request().method() === 'POST');
    await syncBtn.click();
    const syncRes = await syncDone;
    check(syncRes.status() === 200, 'alice ran "Synchronize now" in Beacon', `HTTP ${syncRes.status()}`);
    await sleep(1500);
    await alice.screenshot({ path: join(shots, '5-beacon-keystone-settings.png'), fullPage: true });
    users = (await umApi(alice, 'GET', '/api/users')).data;
    check(byName('bob')?.disabled === true, 'Beacon disabled bob', JSON.stringify({ disabled: byName('bob')?.disabled }));
    check(byName('alice')?.disabled === false, 'alice stays enabled');
    const bobMe = await umApi(bob, 'GET', '/api/auth/me');
    check(bobMe.status === 401, "bob's Beacon session ended", `HTTP ${bobMe.status}`);

    step('bob cannot sign in again');
    await bob.goto(`${umURL}/`);
    await bob.waitForURL((u) => u.href.startsWith(`${spaURL}/signin`), { timeout: 20000 });
    await bob.getByLabel('User name').fill('bob');
    await bob.locator('input[type=password]').fill(PEOPLE.bob.password);
    await bob.getByRole('button', { name: 'Sign in', exact: true }).click();
    await bob.getByText('This account is disabled').waitFor();
    check(true, 'Keystone refuses bob: "This account is disabled"');

    step('Audit log of Keystone');
    const audit = (await spaApi('GET', '/api/v1/audit?q=')).data.map((e) => e.action);
    for (const a of ['application.connected', 'application.roles_published', 'totp.enabled', 'oauth.token', 'user.updated']) {
      check(audit.includes(a), `Keystone audit has ${a}`);
    }
    await alice.screenshot({ path: join(shots, '6-done.png') });
  } catch (e) {
    for (const p of children) {
      const tail = p.logText().split('\n').slice(-25).join('\n');
      console.log(`\n---- last output of ${p.spawnfile}\n${tail}`);
    }
    throw e;
  } finally {
    if (process.env.E2E_KEEP !== '1') await browser.close();
  }
}

let failed = false;
try {
  await main();
} catch (e) {
  failed = true;
  console.error(`\nE2E FAILED: ${e.message}`);
}
const passed = results.filter((r) => r.ok).length;
console.log(`\n${failed ? 'FAILED' : 'PASSED'}: ${passed} checks passed${failed ? ', 1 failed' : ''}. Screenshots: ${join(WORK, 'screens')}`);
writeFileSync(join(WORK, 'result.json'), JSON.stringify({ passed: !failed, checks: results, keystone: spaURL, beacon: umURL }, null, 2));
if (process.env.E2E_KEEP === '1' && !failed) {
  console.log(`Keystone ${spaURL} and Beacon ${umURL} keep running; Ctrl+C stops them.`);
} else {
  stopAll();
  if (!failed && process.env.E2E_KEEP !== '1') {
    try {
      for (const db of ['spa_e2e', 'um_e2e']) psql('postgres', `DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    } catch {
      /* the databases stay for a look */
    }
  }
  process.exit(failed ? 1 : 0);
}
