#!/usr/bin/env node
// Takes the README screenshots (docs/screens/*.png) of a really running Keystone with Playwright (Chromium).
// The demo data comes through Keystone's API (scripts/seed-demo.mjs); start Keystone on an empty database first:
//
//   SPA_URL=http://localhost:8080 SPA_ADMIN_PASSWORD=<initial password> node scripts/screenshots.mjs
//
// Playwright is taken from the project, else from the global npm modules. CHROMIUM may point at a browser binary.
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, DEMO_PASSWORD, seed } from './seed-demo.mjs';

const BASE = process.env.SPA_URL ?? 'http://localhost:8080';
const OUT = fileURLToPath(new URL('../docs/screens/', import.meta.url));
mkdirSync(OUT, { recursive: true });

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

const { chromium } = await loadPlaywright();
const browser = await chromium.launch({ executablePath: chromiumPath() });
const api = new Client(BASE);
await seed(api);

async function context(theme, lang = 'en') {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: theme, locale: lang === 'ru' ? 'ru-RU' : 'en-GB' });
  await ctx.addInitScript(
    ([t, l]) => {
      localStorage.setItem('spa.theme', t);
      localStorage.setItem('lang', l);
    },
    [theme, lang],
  );
  return ctx;
}

async function signedIn(theme, lang) {
  const ctx = await context(theme, lang);
  const page = await ctx.newPage();
  await page.goto(`${BASE}/signin`);
  await page.getByLabel(lang === 'ru' ? 'Имя пользователя' : 'User name').fill('admin');
  await page.locator('input[type=password]').fill(DEMO_PASSWORD);
  await page.locator('form button[type=submit]').click();
  await page.waitForURL(`${BASE}/`);
  await page.waitForSelector('.app-tile');
  return { ctx, page };
}

/** Saves the page; `height` makes the window taller for long pages (the page scrolls inside its block). */
async function shot(page, name, height) {
  if (height) await page.setViewportSize({ width: 1440, height });
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(450); // springs and fades settle
  await page.evaluate(() => document.querySelector('.page')?.scrollTo(0, 0));
  await page.screenshot({ path: join(OUT, `${name}.png`) });
  if (height) await page.setViewportSize({ width: 1440, height: 900 });
  console.log(`docs/screens/${name}.png`);
}

/** A pending sign-in of Beacon: the sign-in page Keystone shows when the application sends a person. */
async function authorizeURL() {
  const { applications } = await api.get('/api/v1/applications');
  const app = applications.find((a) => a.type === 'beacon');
  const q = new URLSearchParams({
    client_id: app.client_id, redirect_uri: app.callback, response_type: 'code', scope: 'openid profile email groups roles',
    state: 'demo-state', nonce: 'demo-nonce', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  });
  return `${BASE}/oauth2/authorize?${q}`;
}

for (const theme of ['light', 'dark']) {
  // Sign-in page (an application asks for the sign-in)
  {
    const ctx = await context(theme);
    const page = await ctx.newPage();
    await page.goto(await authorizeURL());
    await page.waitForSelector('.app-request');
    await shot(page, `signin-${theme}`);
    await ctx.close();
  }
  const { ctx, page } = await signedIn(theme, 'en');
  await shot(page, `home-${theme}`);
  await page.goto(`${BASE}/applications`);
  await page.waitForSelector('.data-table');
  await shot(page, `applications-${theme}`);
  await page.goto(`${BASE}/users`);
  await page.waitForSelector('.data-table');
  await shot(page, `users-${theme}`);
  if (theme === 'light') {
    // Connect wizard: application, access, connection key
    await page.goto(`${BASE}/applications?connect=1`);
    await page.waitForSelector('.type-grid');
    await page.locator('.type-option').filter({ hasText: 'Network Control' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Network Control (lab)');
    await page.getByLabel('Address').fill('https://netctl-lab.umbrella.example');
    await shot(page, 'wizard-1-application');
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('button', { name: 'Add a rule' }).click();
    await page.getByRole('button', { name: 'Add a rule' }).click();
    const rows = page.locator('.rule-row');
    await rows.nth(0).locator('select').nth(1).selectOption({ label: 'Network engineers' });
    await rows.nth(0).locator('select').nth(2).selectOption('admin');
    await rows.nth(1).locator('select').nth(1).selectOption({ label: 'NOC' });
    await rows.nth(1).locator('select').nth(2).selectOption('viewer');
    await shot(page, 'wizard-2-access');
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.waitForSelector('.key-box');
    await shot(page, 'wizard-3-key');
    await page.getByRole('button', { name: 'Done' }).click();

    await page.goto(`${BASE}/groups`);
    await page.waitForSelector('.data-table');
    await shot(page, 'groups');
    await page.getByRole('button', { name: 'New group' }).click();
    await page.getByRole('radio', { name: 'LDAP / AD' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Network Admins');
    await page.getByLabel('Distinguished name (DN)').fill('CN=Network Admins,OU=Groups,DC=umbrella,DC=example');
    await shot(page, 'groups-directory');
    await page.keyboard.press('Escape');

    await page.goto(`${BASE}/settings/password-policy`);
    await page.waitForSelector('.counters');
    await page.getByPlaceholder('Type a password to check it against the rules').fill('Umbrella2026');
    await shot(page, 'password-policy', 1480);
    await page.goto(`${BASE}/settings/directories`);
    await page.waitForSelector('.card');
    await shot(page, 'directories', 1640);
    await page.goto(`${BASE}/settings/providers`);
    await page.waitForSelector('.card');
    await shot(page, 'providers');
    await page.goto(`${BASE}/settings/general`);
    await page.waitForSelector('.card');
    await shot(page, 'general');
    await page.goto(`${BASE}/audit`);
    await page.waitForSelector('.data-table');
    await shot(page, 'audit');
  }
  await page.goto(`${BASE}/profile`);
  await page.waitForSelector('.data-table');
  await shot(page, `profile-${theme}`, theme === 'light' ? 1240 : undefined);
  await ctx.close();
}

// Russian, and the change of an expired password (a person whose administrator set the initial password)
{
  const { ctx, page } = await signedIn('light', 'ru');
  await shot(page, 'home-ru');
  await ctx.close();
  const c2 = await context('light');
  const p2 = await c2.newPage();
  await p2.goto(`${BASE}/signin`);
  await p2.getByLabel('User name').fill('kchen');
  await p2.locator('input[type=password]').fill('Welcome-to-Umbrella-1');
  await p2.locator('form button[type=submit]').click();
  await p2.waitForSelector('text=Choose a new password');
  const pw = p2.locator('input[type=password]');
  await pw.nth(0).fill('Welcome-to-Umbrella-1');
  await pw.nth(2).fill('Kevin-Umbrella-2026');
  await pw.nth(1).fill('Kevin-Umbrella-2026');
  await shot(p2, 'signin-change-password');
  await c2.close();
}

await browser.close();
