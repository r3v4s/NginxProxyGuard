import { test, expect, type APIRequestContext, type Browser, type Page, type Response } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as net from 'net';
import { AccessListPage } from '../../pages';
import { APIHelper, type DNSEntryStatusData } from '../../utils/api-helper';
import { NGINX_HTTP_PORT, ROUTES } from '../../fixtures/test-data';

/**
 * Domain entries in access lists (#320): the list editor and card,
 * rules an older version saved with a name, review and "Allow again", the
 * settings screen, both screens on a phone, roles, and the labels of the new
 * alerts and audit actions.
 *
 * The API container resolves the two names below through extra_hosts in
 * docker-compose.e2e-test.yml, so nothing here is looked up on the internet;
 * a test that saved any other name would send a public DNS query. Their
 * addresses are in 100.64.32.0/24, CGNAT: the address policy refuses the
 * documentation ranges as reserved and allows CGNAT, so a domain can only
 * resolve to such an address here. scripts/pii-scan.sh lists them as IPv4 to
 * check by eye; they are nobody's address.
 *
 * Each host proxies to the API itself (127.0.0.1:19080, which nginx reaches
 * from the host network), so a request NPG lets through gets the API's 404
 * and one it blocks gets NPG's 403. Clients are simulated with
 * X-Forwarded-For from loopback, which nginx always trusts.
 *
 * The compose file makes the API check names every 5 s. A test that changes
 * what a name resolves to rewrites the API container's /etc/hosts in place
 * (a bind mount, so never sed -i); Go reads it again at most 5 s later.
 */
const API = 'http://127.0.0.1:19080';
const UI = process.env.BASE_URL || 'https://localhost:18181';
const API_CONTAINER = process.env.NPG_TEST_API_CONTAINER || 'npg-test-api';
const DB_CONTAINER = process.env.NPG_TEST_DB_CONTAINER || 'npg-test-db';
// What the API answers for "/", which it does not serve.
const PASSED = 404;
// Hosts, lists, auth providers, users and roles of this file start with it.
// The sweeps delete only those: other spec files run alongside.
const PREFIX = 'r2-dns-';
const PARTNER = 'partner.e2e.example';
const PARTNER_IP = '100.64.32.10';
const REVIEW = 'review.e2e.example';
const REVIEW_IP = '100.64.32.20';
const REVIEW_NEW_IP = '100.64.32.21';
// Where review.e2e.example goes while an "Allow again" dialog is open.
const REVIEW_AGAIN_IP = '100.64.32.22';
const REVIEW_MOVED_IP = '100.64.32.23';
// Where review.e2e.example goes before it is allowed again from the domain overview.
const REVIEW_OVERVIEW_IP = '100.64.32.24';
// A client no list of this file allows.
const OUTSIDER = '100.64.32.11';
// Built-in roles (database/migration.go).
const ROLE_OPERATOR = '00000000-0000-0000-0000-0000000000a2';
const ROLE_VIEWER = '00000000-0000-0000-0000-0000000000a3';

test.describe.configure({ mode: 'serial' });

/** Send a GET for "/" with an explicit Host and client address; resolve with the status (0 = no answer). */
function probe(host: string, forwardedFor: string): Promise<number> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: NGINX_HTTP_PORT });
    socket.setTimeout(6000);
    let buf = '';
    const done = (status: number) => {
      socket.destroy();
      resolve(status);
    };
    socket.on('connect', () => {
      socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nX-Forwarded-For: ${forwardedFor}\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      if (m) done(Number(m[1]));
    });
    socket.on('close', () => done(0));
    socket.on('error', () => done(0));
    socket.on('timeout', () => done(0));
  });
}

async function eventually(fn: () => Promise<boolean>, what: string, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`never: ${what}`);
}

/**
 * Has the open page read the access lists again in the background, as it does
 * when its tab is shown again and the data it holds is older than 30 s.
 */
async function refetchListsInBackground(page: Page): Promise<void> {
  let refetched = false;
  const seen = (res: Response) => {
    if (res.request().method() === 'GET' && new URL(res.url()).pathname === '/api/v1/access-lists') refetched = true;
  };
  page.on('response', seen);
  try {
    await eventually(
      async () => {
        await page.evaluate(() => window.dispatchEvent(new Event('visibilitychange')));
        return refetched;
      },
      'the page reads the access lists again',
      60_000,
    );
  } finally {
    page.off('response', seen);
  }
}

function uuid(id: string): string {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error(`not a UUID: ${id}`);
  return id;
}

/** One SQL statement against the e2e database, output trimmed. Values are this file's constants or checked UUIDs. */
function sql(statement: string): string {
  return execFileSync(
    'docker',
    ['exec', DB_CONTAINER, 'psql', '-U', 'postgres', '-d', 'nginx_guard_test', '-tAc', statement],
    { encoding: 'utf-8' },
  ).trim();
}

/** A list's stored rules as "directive|address|hostname", in rule order. */
function rulesOf(listId: string): string[] {
  const rows = sql(
    `SELECT string_agg(directive || '|' || address || '|' || COALESCE(hostname, ''), ',' ORDER BY sort_order) ` +
      `FROM access_list_items WHERE access_list_id = '${uuid(listId)}'`,
  );
  return rows === '' ? [] : rows.split(',');
}

function readHosts(): string {
  return execFileSync('docker', ['exec', API_CONTAINER, 'cat', '/etc/hosts'], { encoding: 'utf-8' });
}

/** The address the API container's /etc/hosts gives name, or '' without a line for it. */
function hostsEntry(name: string): string {
  for (const line of readHosts().split('\n')) {
    const [addr, first] = line.trim().split(/\s+/);
    if (first === name) return addr;
  }
  return '';
}

/** Points name at addr in the API container's /etc/hosts. The file is a bind mount, so it is rewritten in place. */
function setHostsEntry(name: string, addr: string): void {
  const kept = readHosts()
    .split('\n')
    .filter((line) => line.trim() !== '' && line.trim().split(/\s+/)[1] !== name);
  kept.push(`${addr}\t${name}`);
  execFileSync('docker', ['exec', '-i', API_CONTAINER, 'sh', '-c', 'cat > /etc/hosts'], {
    input: `${kept.join('\n')}\n`,
    encoding: 'utf-8',
  });
}

type Named = { id: string; name?: string; username?: string; domain_names?: string[] };

async function listOf(ctx: APIRequestContext, path: string, headers: Record<string, string>): Promise<Named[]> {
  const res = await ctx.get(path, { headers });
  if (!res.ok()) return [];
  const body = await res.json();
  return (Array.isArray(body) ? body : body.data) ?? [];
}

/** Deletes what this file makes, by prefix: what a failed earlier run left, or this run's at the end. */
async function sweep(ctx: APIRequestContext): Promise<void> {
  const helper = new APIHelper(ctx);
  await helper.login();
  const headers = { Authorization: `Bearer ${await helper.getToken()}` };
  const del = (path: string) => ctx.delete(path, { headers }).catch(() => undefined);
  // Hosts first: they use the lists and the auth providers.
  for (const h of await listOf(ctx, '/api/v1/proxy-hosts?per_page=100', headers)) {
    if (h.domain_names?.[0]?.startsWith(PREFIX)) await del(`/api/v1/proxy-hosts/${h.id}`);
  }
  for (const p of await listOf(ctx, '/api/v1/auth-providers?per_page=100', headers)) {
    if (p.name?.startsWith(PREFIX)) await del(`/api/v1/auth-providers/${p.id}`);
  }
  for (const l of await listOf(ctx, '/api/v1/access-lists?per_page=100', headers)) {
    if (l.name?.startsWith(PREFIX)) await del(`/api/v1/access-lists/${l.id}`);
  }
  // Users before roles: a role a user still has cannot go.
  for (const u of await listOf(ctx, '/api/v1/users', headers)) {
    if (u.username?.startsWith(PREFIX)) await del(`/api/v1/users/${u.id}`);
  }
  for (const r of await listOf(ctx, '/api/v1/roles', headers)) {
    if (r.name?.startsWith(PREFIX)) await del(`/api/v1/roles/${r.id}`);
  }
}

// The password an account made by createRoleUser ends up with.
const ROLE_USER_PASSWORD = 'E2e-Next-Pass-34!';

interface RoleUser {
  id: string;
  username: string;
  token: string;
}

/** An account an administrator made with role roleId, past its forced password change. */
async function createRoleUser(
  request: APIRequestContext,
  headers: Record<string, string>,
  roleId: string,
  label: string,
): Promise<RoleUser> {
  const username = `${PREFIX}${label}-${Date.now()}`;
  const first = 'E2e-First-Pass-12!';
  const next = ROLE_USER_PASSWORD;
  const created = await request.post(`${API}/api/v1/users`, { headers, data: { username, password: first, role_id: roleId } });
  expect(created.status(), await created.text()).toBe(201);
  const id = (await created.json()).id as string;
  const login = await request.post(`${API}/api/v1/auth/login`, { data: { username, password: first } });
  expect(login.ok(), `login of ${username}`).toBeTruthy();
  const token = (await login.json()).token as string;
  // Such an account may do nothing else until it picks its own password.
  const changed = await request.post(`${API}/api/v1/auth/change-password`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { current_password: first, new_password: next, new_password_confirm: next },
  });
  expect(changed.status(), await changed.text()).toBe(200);
  return { id, username, token };
}

/** A browser context signed in with token, in English, recording every 403 the UI gets from the API. */
async function openAs(browser: Browser, token: string): Promise<{ page: Page; forbidden: string[]; close: () => Promise<void> }> {
  const context = await browser.newContext({ baseURL: UI, ignoreHTTPSErrors: true });
  await context.addInitScript((t: string) => {
    window.localStorage.setItem('npg_token', t);
    window.localStorage.setItem('npg_language', 'en');
  }, token);
  const page = await context.newPage();
  const forbidden: string[] = [];
  page.on('response', (res) => {
    if (res.status() === 403 && res.url().includes('/api/')) {
      forbidden.push(`${res.request().method()} ${new URL(res.url()).pathname}`);
    }
  });
  return { page, forbidden, close: () => context.close() };
}

/**
 * A browser context in English that signs in through the login page, so the
 * page a role lands on fires its own requests; every 403 the UI gets from the
 * API is recorded from the first request on.
 */
async function signInAs(
  browser: Browser,
  username: string,
  password: string,
): Promise<{ page: Page; forbidden: string[]; close: () => Promise<void> }> {
  // Signed out: the project's stored admin session would otherwise come along.
  const context = await browser.newContext({ baseURL: UI, ignoreHTTPSErrors: true, storageState: { cookies: [], origins: [] } });
  await context.addInitScript(() => window.localStorage.setItem('npg_language', 'en'));
  const page = await context.newPage();
  const forbidden: string[] = [];
  page.on('response', (res) => {
    if (res.status() === 403 && res.url().includes('/api/')) {
      forbidden.push(`${res.request().method()} ${new URL(res.url()).pathname}`);
    }
  });
  await page.goto('/');
  await page.locator('input#username').fill(username);
  await page.locator('input#password').fill(password);
  await page.locator('button[type="submit"]').click();
  await expect(page.locator('input#password')).toHaveCount(0, { timeout: 15_000 });
  return { page, forbidden, close: () => context.close() };
}

test.describe('Domain entries in access lists (#320)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  // The list the first test makes in the editor; later tests use it too.
  let partnerList: { id: string; name: string };

  test.beforeAll(async ({ playwright }) => {
    for (const name of [PARTNER, REVIEW]) {
      if (!hostsEntry(name)) {
        throw new Error(
          `${name} is not in ${API_CONTAINER}'s /etc/hosts: bring the e2e stack up from docker-compose.e2e-test.yml, whose api extra_hosts lists it`,
        );
      }
    }
    // A failed earlier run may have left a name pointing elsewhere.
    setHostsEntry(PARTNER, PARTNER_IP);
    setHostsEntry(REVIEW, REVIEW_IP);
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      await sweep(ctx);
      const helper = new APIHelper(ctx);
      await helper.login();
      const overview = await ctx.get('/api/v1/dns-entries', { headers: { Authorization: `Bearer ${await helper.getToken()}` } });
      expect(overview.status(), 'GET /api/v1/dns-entries').toBe(200);
      expect((await overview.json()).env_interval_seconds, 'NPG_DNS_ENTRIES_INTERVAL of the e2e api').toBe(5);
    } finally {
      await ctx.dispose();
    }
    // A name no list uses keeps its state for 7 days, review included: start these two from none.
    sql(
      `DELETE FROM dns_entry_states s WHERE s.hostname IN ('${PARTNER}', '${REVIEW}') ` +
        `AND NOT EXISTS (SELECT 1 FROM access_list_items i WHERE i.hostname = s.hostname)`,
    );
  });

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      await sweep(ctx);
    } finally {
      await ctx.dispose();
    }
    setHostsEntry(PARTNER, PARTNER_IP);
    setHostsEntry(REVIEW, REVIEW_IP);
  });

  async function createHost(prefix: string, extra: Record<string, unknown> = {}): Promise<{ id: string; domain: string }> {
    const domain = `${prefix}-${Date.now()}.example.com`;
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 19080,
      enabled: true,
      ...extra,
    });
    return { id: host.id, domain };
  }

  /** The DNS state a list's GET shows for one of its domains. */
  async function dnsOf(listId: string, name: string): Promise<DNSEntryStatusData | null | undefined> {
    const list = await api.getAccessList(listId);
    return list.items?.find((item) => item.kind === 'hostname' && item.address === name)?.dns;
  }

  test('a domain added in the list editor is looked up at once, applied and shown with its state', async ({ page }) => {
    test.setTimeout(90_000);
    const name = `${PREFIX}partner-${Date.now()}`;
    const lists = new AccessListPage(page);
    await lists.goto();
    // The address cell takes a domain like an IP; the editor sends it as kind "hostname".
    await lists.createList({ name, allowedIps: [PARTNER] });

    const list = (await api.getAccessLists()).find((l) => l.name === name);
    expect(list, `access list ${name}`).toBeDefined();
    partnerList = { id: list!.id, name };
    const item = list!.items?.find((i) => i.address === PARTNER);
    expect(item).toMatchObject({ kind: 'hostname', directive: 'allow' });
    // The save looked the new name up (at most 3 s) and published its first answer.
    expect(item?.dns?.status).toBe('ok');
    expect(item?.dns?.addresses).toEqual([PARTNER_IP]);
    // Stored as the row an older version reads as "deny all".
    expect(rulesOf(list!.id)).toEqual([`deny|all|${PARTNER}`]);
    // Warnings are worked out at the end of a check (every 5 s here), not by the save.
    await eventually(
      async () => ((await dnsOf(list!.id, PARTNER))?.warnings ?? []).includes('cgnat'),
      'the CGNAT warning',
      30_000,
    );

    const host = await createHost(`${PREFIX}h`, { access_list_id: list!.id });
    await eventually(async () => (await probe(host.domain, PARTNER_IP)) === PASSED, 'the domain address passes');
    expect(await probe(host.domain, OUTSIDER), 'a client the list does not allow').toBe(403);

    await lists.goto();
    await lists.expandList(name);
    const entry = lists.dnsEntry(name, PARTNER);
    await expect(entry.locator('[data-status="ok"]')).toBeVisible();
    await expect(entry).toContainText(PARTNER_IP);
  });

  test('a satisfy-any list names the login hosts its domains get past', async ({ browser, page, request }) => {
    test.setTimeout(90_000);
    // The verifier is the API's own /api/v1/auth/me: 200 with a session token, 401 without.
    const providerRes = await request.post(`${API}/api/v1/auth-providers`, {
      headers,
      data: {
        name: `${PREFIX}fa-${Date.now()}`,
        type: 'custom',
        provider_url: API,
        timeout_ms: 3000,
        enabled: true,
        config: {
          verify_path: '/api/v1/auth/me',
          signin_mode: 'redirect_template',
          signin_redirect: 'https://login.example.com/',
        },
      },
    });
    expect(providerRes.status()).toBe(201);
    const providerId = (await providerRes.json()).id as string;
    const host = await createHost(`${PREFIX}fa`, { access_list_id: partnerList.id, auth_provider_id: providerId });

    // The editor made the list "satisfy any": the domain's address gets in
    // without the login, anybody else is sent to sign in.
    await eventually(async () => (await probe(host.domain, PARTNER_IP)) === PASSED, 'the domain address skips the login');
    expect(await probe(host.domain, OUTSIDER), 'a client outside the list signs in').toBe(302);

    // The list says so once the next check has indexed the host.
    await eventually(
      async () => (await api.getAccessList(partnerList.id)).login_bypass_hosts?.count === 1,
      'the list counts the login host',
      30_000,
    );
    const bypass = (await api.getAccessList(partnerList.id)).login_bypass_hosts;
    expect(bypass?.hosts?.map((h) => h.domain)).toEqual([host.domain]);

    const lists = new AccessListPage(page);
    await lists.goto();
    await lists.expandList(partnerList.name);
    const note = lists
      .getListByName(partnerList.name)
      .getByRole('note')
      .filter({ hasText: /domains can skip the login|로그인을 건너뛸/i });
    await expect(note).toContainText(host.domain);

    // Without proxy:read the list says how many login hosts there are, not which.
    const roleRes = await request.post(`${API}/api/v1/roles`, {
      headers,
      data: { name: `${PREFIX}lists-reader-${Date.now()}`, description: 'e2e', permissions: ['access:read'] },
    });
    expect(roleRes.status()).toBe(201);
    const reader = await createRoleUser(request, headers, (await roleRes.json()).id as string, 'lists-reader');
    const asReader = await request.get(`${API}/api/v1/access-lists/${partnerList.id}`, {
      headers: { Authorization: `Bearer ${reader.token}` },
    });
    expect(asReader.status()).toBe(200);
    expect((await asReader.json()).login_bypass_hosts).toEqual({ count: 1, hosts: null });
    const session = await openAs(browser, reader.token);
    try {
      const readerLists = new AccessListPage(session.page);
      await readerLists.goto();
      await readerLists.expandList(partnerList.name);
      const readerNote = readerLists
        .getListByName(partnerList.name)
        .getByRole('note')
        .filter({ hasText: /domains can skip the login|로그인을 건너뛸/i });
      await expect(readerNote).toContainText(/applies to 1 host|로그인 호스트 1곳/i);
      await expect(readerNote).not.toContainText(host.domain);
    } finally {
      await session.close();
    }
  });

  test('a rule an older version saved with a name stays unapplied until it is moved to a domain', async ({ page }) => {
    test.setTimeout(90_000);
    const name = `${PREFIX}legacy-${Date.now()}`;
    const list = await api.createAccessList({
      name,
      satisfy_any: false,
      items: [{ directive: 'allow', address: '192.0.2.44', kind: 'address', sort_order: 0 }],
    });
    // What an older version stored: a name in the address column, no hostname.
    sql(
      `INSERT INTO access_list_items (access_list_id, directive, address, sort_order) ` +
        `VALUES ('${uuid(list.id)}', 'allow', '${PARTNER}', 1)`,
    );
    const stored = await api.getAccessList(list.id);
    expect(stored.items?.find((i) => i.address === PARTNER)).toMatchObject({ kind: 'legacy', effect: 'ignored' });

    const lists = new AccessListPage(page);
    await lists.goto();
    await lists.clickList(name);
    await expect(lists.legacyRules()).toHaveCount(1);
    await expect(lists.legacyRules().first()).toContainText(`allow ${PARTNER}`);
    await expect(lists.legacyRules().first()).toContainText(/not applied|적용 안 됨/i);

    // Renaming the list sends the legacy row back as it was: it stays legacy.
    const renamed = `${name}-renamed`;
    await lists.fillName(renamed);
    await lists.save();
    expect(rulesOf(list.id)).toEqual(['allow|192.0.2.44|', `allow|${PARTNER}|`]);
    expect((await api.getAccessList(list.id)).items?.find((i) => i.address === PARTNER)?.kind).toBe('legacy');

    // Only "Move to domain" turns it into a domain entry.
    await lists.clickList(renamed);
    await lists.moveLegacyRuleToDomain(PARTNER);
    await expect(lists.legacyRules()).toHaveCount(0);
    await lists.save();
    expect(rulesOf(list.id)).toEqual(['allow|192.0.2.44|', `deny|all|${PARTNER}`]);
    const moved = (await api.getAccessList(list.id)).items?.find((i) => i.address === PARTNER);
    expect(moved).toMatchObject({ kind: 'hostname', directive: 'allow' });
    expect(moved?.dns?.status).toBe('ok');
    expect(
      sql(
        `SELECT details->>'moved_to_domain' FROM audit_logs ` +
          `WHERE action = 'access_list_updated' AND resource_name = '${renamed}' ORDER BY created_at DESC LIMIT 1`,
      ),
    ).toBe(`["${PARTNER}"]`);
  });

  test('a domain that comes back with an address it never had waits for review and is allowed again', async ({ page }) => {
    test.setTimeout(150_000);
    const name = `${PREFIX}review-${Date.now()}`;
    const list = await api.createAccessList({
      name,
      satisfy_any: false,
      items: [{ directive: 'allow', address: REVIEW, kind: 'hostname', sort_order: 0 }],
    });
    expect(list.items?.[0]?.dns?.status, 'first answer published at save').toBe('ok');
    const host = await createHost(`${PREFIX}rv`, { access_list_id: list.id });
    await eventually(async () => (await probe(host.domain, REVIEW_IP)) === PASSED, 'the first address passes');

    // Loopback is refused at once, and the name's file empties.
    setHostsEntry(REVIEW, '127.0.0.1');
    await eventually(async () => (await dnsOf(list.id, REVIEW))?.status === 'rejected', 'the loopback answer is refused', 40_000);
    await eventually(async () => (await probe(host.domain, REVIEW_IP)) === 403, 'the old address is revoked', 30_000);

    // Back with an address it never had: closed until someone confirms it.
    setHostsEntry(REVIEW, REVIEW_NEW_IP);
    await eventually(
      async () => (await dnsOf(list.id, REVIEW))?.status === 'needs_review',
      'the new address waits for review',
      40_000,
    );
    expect(await probe(host.domain, REVIEW_NEW_IP)).toBe(403);
    expect((await dnsOf(list.id, REVIEW))?.review_reason).toBe('reappeared');
    const alertState = () =>
      sql(`SELECT state FROM notification_state WHERE event_key = 'dns_entry.review' AND subject = '${REVIEW}'`);
    await eventually(async () => alertState() === 'failing', 'the review alert is open', 30_000);

    // "Allow again" shows what the server resolves now and publishes only that.
    const lists = new AccessListPage(page);
    await lists.goto();
    await lists.expandList(name);
    const entry = lists.dnsEntry(name, REVIEW);
    await expect(entry.locator('[data-status="needs_review"]')).toBeVisible();
    await entry.getByRole('button', { name: /^(allow again|다시 허용)$/i }).click();
    const dialog = page.getByRole('dialog', { name: new RegExp(REVIEW.replace(/\./g, '\\.')) });
    await expect(dialog).toContainText(REVIEW_NEW_IP);
    await dialog.getByRole('button', { name: /^(allow again|다시 허용)$/i }).click();
    await expect(dialog).toBeHidden({ timeout: 15_000 });
    await expect(entry.locator('[data-status="ok"]')).toBeVisible({ timeout: 15_000 });

    await eventually(async () => (await probe(host.domain, REVIEW_NEW_IP)) === PASSED, 'the confirmed address passes', 20_000);
    expect(await probe(host.domain, REVIEW_IP), 'the address it had before').toBe(403);
    await eventually(async () => alertState() === 'ok', 'the review alert is closed', 30_000);
    expect(
      Number(sql(`SELECT count(*) FROM audit_logs WHERE action = 'dns_entry_confirmed' AND resource_name = '${REVIEW}'`)),
    ).toBeGreaterThan(0);
  });

  test('"Allow again" on an answer that moved meanwhile is refused, shows the new answer and allows that', async ({ page }) => {
    test.setTimeout(150_000);
    // The previous test allowed REVIEW again at REVIEW_NEW_IP; this list uses it too.
    const name = `${PREFIX}recheck-${Date.now()}`;
    const list = await api.createAccessList({
      name,
      satisfy_any: false,
      items: [{ directive: 'allow', address: REVIEW, kind: 'hostname', sort_order: 0 }],
    });
    const host = await createHost(`${PREFIX}rc`, { access_list_id: list.id });
    await eventually(async () => (await probe(host.domain, REVIEW_NEW_IP)) === PASSED, 'the allowed address passes');

    // Into review again: refused, then an address it never had.
    setHostsEntry(REVIEW, '127.0.0.1');
    await eventually(async () => (await dnsOf(list.id, REVIEW))?.status === 'rejected', 'the loopback answer is refused', 40_000);
    setHostsEntry(REVIEW, REVIEW_AGAIN_IP);
    await eventually(
      async () => (await dnsOf(list.id, REVIEW))?.status === 'needs_review',
      'the new address waits for review',
      40_000,
    );

    const lists = new AccessListPage(page);
    await lists.goto();
    await lists.expandList(name);
    const entry = lists.dnsEntry(name, REVIEW);
    await entry.getByRole('button', { name: /^(allow again|다시 허용)$/i }).click();
    const dialog = page.getByRole('dialog', { name: new RegExp(REVIEW.replace(/\./g, '\\.')) });
    await expect(dialog).toContainText(REVIEW_AGAIN_IP);

    // The name moves on while the dialog is open, and a check records the new answer.
    setHostsEntry(REVIEW, REVIEW_MOVED_IP);
    await eventually(
      async () => ((await dnsOf(list.id, REVIEW))?.observed_addresses ?? []).includes(REVIEW_MOVED_IP),
      'a check sees the moved address',
      40_000,
    );
    // The page reads the lists again behind the dialog: the dialog keeps the answer it showed.
    await refetchListsInBackground(page);
    await expect(dialog).toContainText(REVIEW_AGAIN_IP);
    // It still offers what it read: the server refuses that with a 409 and the dialog reads the name again.
    await expect(dialog).not.toContainText(REVIEW_MOVED_IP);
    const allow = dialog.getByRole('button', { name: /^(allow again|다시 허용)$/i });
    const refused = page.waitForResponse((res) => res.url().includes('/dns-confirm') && res.request().method() === 'POST');
    await allow.click();
    expect((await refused).status(), 'confirming an answer the server no longer sees').toBe(409);
    await expect(dialog).toContainText(/the dns answer changed|DNS 응답이 바뀌어/i);
    await expect(dialog).toContainText(REVIEW_MOVED_IP);
    await expect(dialog).not.toContainText(REVIEW_AGAIN_IP);

    // Confirming what it shows now allows exactly that.
    await allow.click();
    await expect(dialog).toBeHidden({ timeout: 15_000 });
    await expect(entry.locator('[data-status="ok"]')).toBeVisible({ timeout: 15_000 });
    await eventually(async () => (await probe(host.domain, REVIEW_MOVED_IP)) === PASSED, 'the confirmed address passes', 20_000);
    expect(await probe(host.domain, REVIEW_AGAIN_IP), 'the address the dialog showed first').toBe(403);
  });

  test('the address cell refuses a name that would change on conversion, before anything is sent', async ({ page }) => {
    const writes: string[] = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/access-lists') && req.method() !== 'GET') writes.push(`${req.method()} ${req.url()}`);
    });
    const lists = new AccessListPage(page);
    await lists.goto();
    await lists.clickAddList();
    await lists.fillName(`${PREFIX}refused-${Date.now()}`);
    // A non-ASCII name is shown with the xn-- form it would be saved as.
    await lists.addAllowedIp('bücher.example');
    await expect(lists.modal).toContainText('xn--bcher-kva.example');
    // A URL parser would turn "ü@evil.example" into "evil.example": it is refused as typed.
    await lists.addAllowedIp('ü@evil.example');
    await lists.saveButton.click();
    await expect(lists.modal).toContainText(/without a scheme, port, path, % or @|스킴·포트·경로·%·@ 없이/);
    expect(writes, 'requests that would save the list').toEqual([]);
    await lists.cancel();
  });

  test('the settings screen saves the tunables and locks the interval the environment sets', async ({ page, request }) => {
    const read = async () => (await (await request.get(`${API}/api/v1/system-settings`, { headers })).json()).dns_entry_settings;
    const before = await read();
    const target = before.max_changes_per_day === 7 ? 8 : 7;
    try {
      await page.goto(ROUTES.settingsDnsEntries);
      const perDay = page.locator('input[name="max_changes_per_day"]');
      await expect(perDay).toBeVisible({ timeout: 15_000 });
      // NPG_DNS_ENTRIES_INTERVAL is set for this stack, so the interval cannot be edited here.
      await expect(page.locator('input[name="check_interval_seconds"]')).toBeDisabled();
      await perDay.fill(String(target));
      await page.locator('form', { has: perDay }).locator('button[type="submit"]').click();
      await eventually(async () => (await read()).max_changes_per_day === target, 'the setting is stored', 10_000);
      await page.reload();
      await expect(page.locator('input[name="max_changes_per_day"]')).toHaveValue(String(target));
      // The overview lists the domains in use, one row each.
      await expect(page.locator(`tr[data-testid="dns-overview-row"][data-hostname="${PARTNER}"]`)).toBeVisible();
      // Audited with [before, after] for the key that changed.
      const changed = sql(
        `SELECT details->'max_changes_per_day' FROM audit_logs WHERE action = 'dns_entry_settings_changed' ORDER BY created_at DESC LIMIT 1`,
      );
      expect(JSON.parse(changed)).toEqual([before.max_changes_per_day, target]);
    } finally {
      await request.put(`${API}/api/v1/system-settings`, {
        headers,
        data: { dns_entry_settings: { max_changes_per_day: before.max_changes_per_day } },
      });
    }
    // A value out of range is refused with the key's path and changes nothing.
    const refused = await request.put(`${API}/api/v1/system-settings`, {
      headers,
      data: { dns_entry_settings: { check_interval_seconds: 5 } },
    });
    expect(refused.status()).toBe(400);
    expect((await refused.json()).error).toContain('dns_entry_settings.check_interval_seconds');
    expect((await read()).check_interval_seconds).toBe(before.check_interval_seconds);
    // "Apply now" runs the applier once and says on the screen what nginx did.
    const notices: Record<string, RegExp> = {
      accepted: /nginx loaded the domain entry files|nginx가 도메인 항목 파일을 읽었습니다/,
      signalled: /nginx was told to reload the domain entry files|nginx에 도메인 항목 파일을 다시 읽으라고 보냈습니다/,
      unconfirmed: /not confirmed yet that it took the files|파일을 읽었는지 아직 확인하지 못했습니다/,
    };
    await page.goto(ROUTES.settingsDnsEntries);
    const applied = page.waitForResponse((res) => res.url().includes('/api/v1/dns-entries/apply') && res.request().method() === 'POST');
    await page.getByTestId('dns-entries-apply').click();
    const response = await applied;
    expect(response.status()).toBe(200);
    const outcome = (await response.json()).outcome as string;
    expect(Object.keys(notices)).toContain(outcome);
    await expect(page.getByTestId('dns-entry-notice')).toContainText(notices[outcome]);
  });

  test('"Allow again" on the domain overview allows a domain in review', async ({ page, request }) => {
    test.setTimeout(150_000);
    const overviewOf = async () => {
      const res = await request.get(`${API}/api/v1/dns-entries`, { headers });
      return ((await res.json()).entries ?? []).find((e: { hostname: string }) => e.hostname === REVIEW) as
        | DNSEntryStatusData
        | undefined;
    };
    // The lists of the review tests still use it, allowed at REVIEW_MOVED_IP. Into
    // review again: refused, then an address it never had.
    setHostsEntry(REVIEW, '127.0.0.1');
    await eventually(async () => (await overviewOf())?.status === 'rejected', 'the loopback answer is refused', 40_000);
    setHostsEntry(REVIEW, REVIEW_OVERVIEW_IP);
    await eventually(async () => (await overviewOf())?.status === 'needs_review', 'the new address waits for review', 40_000);

    await page.goto(ROUTES.settingsDnsEntries);
    const row = page.locator(`tr[data-testid="dns-overview-row"][data-hostname="${REVIEW}"]`);
    await expect(row.locator('[data-status="needs_review"]')).toBeVisible({ timeout: 15_000 });
    await row.getByRole('button', { name: /^(allow again|다시 허용)$/i }).click();
    const dialog = page.getByRole('dialog', { name: new RegExp(REVIEW.replace(/\./g, '\\.')) });
    await expect(dialog).toContainText(REVIEW_OVERVIEW_IP);
    await dialog.getByRole('button', { name: /^(allow again|다시 허용)$/i }).click();
    await expect(dialog).toBeHidden({ timeout: 15_000 });
    await expect(page.getByTestId('dns-entry-notice')).toContainText(/is allowed again|다시 허용했습니다/);
    await expect(row.locator('[data-status="ok"]')).toBeVisible({ timeout: 15_000 });
    const confirmed = await overviewOf();
    expect(confirmed?.addresses).toEqual([REVIEW_OVERVIEW_IP]);
  });

  test('on a phone the list card and the domain overview fit the screen', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 375, height: 812 });
    const scrollsSideways = () =>
      page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);

    const lists = new AccessListPage(page);
    await lists.goto();
    await lists.expandList(partnerList.name);
    await expect(lists.dnsEntry(partnerList.name, PARTNER)).toContainText(PARTNER_IP);
    expect(await scrollsSideways(), 'the access lists page scrolls sideways').toBe(false);
    const cardShot = testInfo.outputPath('access-list-card-375.png');
    await lists.getListByName(partnerList.name).screenshot({ path: cardShot });
    await testInfo.attach('access list card at 375 px', { path: cardShot, contentType: 'image/png' });

    await page.goto(ROUTES.settingsDnsEntries);
    const row = page.locator(`tr[data-testid="dns-overview-row"][data-hostname="${PARTNER}"]`);
    await expect(row).toBeVisible({ timeout: 15_000 });
    // The table is wider than a phone: it scrolls inside its card, the page does not.
    const scroller = row.locator('xpath=ancestor::div[contains(@class, "overflow-x-auto")][1]');
    expect(await scroller.evaluate((el) => el.scrollWidth > el.clientWidth), 'the table scrolls inside its card').toBe(true);
    expect(await scrollsSideways(), 'the domain entries page scrolls sideways').toBe(false);
    const tableShot = testInfo.outputPath('dns-overview-375.png');
    await row.locator('xpath=ancestor::section[1]').screenshot({ path: tableShot });
    await testInfo.attach('domain overview at 375 px', { path: tableShot, contentType: 'image/png' });
  });

  test('viewer and operator see the domains without a 403, and a settings-only role sees no list names', async ({
    browser,
    request,
  }) => {
    test.setTimeout(120_000);
    const viewer = await createRoleUser(request, headers, ROLE_VIEWER, 'viewer');
    const operator = await createRoleUser(request, headers, ROLE_OPERATOR, 'operator');

    for (const [label, user, canWrite] of [
      ['viewer', viewer, false],
      ['operator', operator, true],
    ] as const) {
      const session = await openAs(browser, user.token);
      try {
        const lists = new AccessListPage(session.page);
        await lists.goto();
        await lists.expandList(partnerList.name);
        await expect(lists.dnsEntry(partnerList.name, PARTNER)).toBeVisible();
        const card = lists.getListByName(partnerList.name);
        if (canWrite) {
          await expect(card.getByRole('button', { name: /^(edit|편집)$/i })).toBeVisible();
          // The editor of a list with domains asks for nothing an operator may not read.
          await lists.clickList(partnerList.name);
          await lists.cancel();
        } else {
          await expect(session.page.getByRole('button', { name: /add access list|접근 목록 추가/i })).toHaveCount(0);
          await expect(card.getByRole('button', { name: /^(edit|delete|편집|삭제)$/i })).toHaveCount(0);
        }
        await session.page.goto(ROUTES.proxyHosts);
        await session.page.waitForLoadState('networkidle');
        expect(session.forbidden, `${label}: 403 answers to the screens`).toEqual([]);
      } finally {
        await session.close();
      }
      // The overview needs settings:read, which neither role has; none of their screens asks for it.
      const overview = await request.get(`${API}/api/v1/dns-entries`, { headers: { Authorization: `Bearer ${user.token}` } });
      expect(overview.status(), `${label}: GET /api/v1/dns-entries`).toBe(403);
    }

    // A viewer who signs in through the login page lands on the dashboard and
    // opens the lists without a 403 either.
    const signedIn = await signInAs(browser, viewer.username, ROLE_USER_PASSWORD);
    try {
      await expect(signedIn.page).toHaveURL(/\/dashboard/);
      await signedIn.page.waitForLoadState('networkidle');
      const lists = new AccessListPage(signedIn.page);
      await lists.goto();
      await lists.expandList(partnerList.name);
      await expect(lists.dnsEntry(partnerList.name, PARTNER).locator('[data-status="ok"]')).toBeVisible();
      expect(signedIn.forbidden, 'viewer: 403 answers from the login on').toEqual([]);
    } finally {
      await signedIn.close();
    }

    // A role with settings:read only sees the domains, not the lists that use them.
    const roleRes = await request.post(`${API}/api/v1/roles`, {
      headers,
      data: { name: `${PREFIX}settings-reader-${Date.now()}`, description: 'e2e', permissions: ['settings:read'] },
    });
    expect(roleRes.status()).toBe(201);
    const reader = await createRoleUser(request, headers, (await roleRes.json()).id as string, 'reader');
    const limited = await request.get(`${API}/api/v1/dns-entries`, { headers: { Authorization: `Bearer ${reader.token}` } });
    expect(limited.status()).toBe(200);
    const hidden = ((await limited.json()).entries ?? []).find((e: { hostname: string }) => e.hostname === PARTNER);
    expect(hidden?.uses ?? []).toEqual([]);
    expect(hidden?.hidden_uses).toBeGreaterThanOrEqual(1);
    const full = await (await request.get(`${API}/api/v1/dns-entries`, { headers })).json();
    const shown = (full.entries ?? []).find((e: { hostname: string }) => e.hostname === PARTNER);
    expect((shown?.uses ?? []).map((u: { owner_name: string }) => u.owner_name)).toContain(partnerList.name);
  });

  test('the new alert events and audit actions have their labels', async ({ page }) => {
    await page.goto(ROUTES.settingsNotifications);
    await page.getByRole('button', { name: /add channel|채널 추가/i }).click();
    const events = page.getByTestId('notify-event-list');
    await expect(events).toContainText('Domain entry needs review');
    await expect(events).toContainText('Domain entry change not applied');
    await expect(page.getByTestId('notify-event-dns_entry.review-off')).toBeVisible();
    await expect(page.getByTestId('notify-event-dns_entry.apply_failed-off')).toBeVisible();

    await page.goto(ROUTES.logsAudit);
    const search = page.getByPlaceholder(/search|검색/i).first();
    await search.fill('dns_entry_confirmed');
    await expect(page.getByText('Domain Entry Confirmed').first()).toBeVisible({ timeout: 15_000 });
    await search.fill('dns_entry_settings_changed');
    await expect(page.getByText('Domain Entry Settings Changed').first()).toBeVisible({ timeout: 15_000 });
  });
});
