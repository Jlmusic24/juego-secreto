'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');
const sec = require('../src/security');

let ctx, base, adminSecret;

before(async () => {
  ctx = createApp({ dbPath: ':memory:', cookieSecure: false });
  await new Promise((r) => ctx.server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${ctx.server.address().port}`;
  adminSecret = sec.generateTotpSecret();
  ctx.db.prepare("INSERT INTO users (email, name, password_hash, role, status, totp_secret, created_at) VALUES (?, ?, ?, 'admin', 'active', ?, ?)")
    .run('admin@test.com', 'Admin', await sec.hashPassword('Admin-Pass-123!'), adminSecret, Date.now());
});

after(() => ctx.close());

function client() {
  let cookie = '';
  return async function req(path, { method = 'GET', body, headers = {} } = {}) {
    const res = await fetch(base + path, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(method !== 'GET' ? { Origin: base, 'X-Requested-With': 'LicitApp' } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    return { status: res.status, data: await res.json().catch(() => null), headers: res.headers };
  };
}

let totpOffset = 0;
// Cada código solo sirve una vez: usamos el intervalo actual y luego el siguiente (tolerancia ±1).
const nextTotp = () => sec.totpNow(adminSecret, Date.now() + 30000 * totpOffset++);

async function loginAdmin() {
  const c = client();
  const first = await c('/api/auth/login', { method: 'POST', body: { email: 'admin@test.com', password: 'Admin-Pass-123!' } });
  assert.equal(first.status, 401);
  assert.equal(first.data.totp_required, true);
  const ok = await c('/api/auth/login', { method: 'POST', body: { email: 'admin@test.com', password: 'Admin-Pass-123!', totp: nextTotp() } });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  return c;
}

async function newBidder(admin, email) {
  const c = client();
  const r = await c('/api/auth/register', { method: 'POST', body: { email, name: email.split('@')[0], password: 'Postor-Pass-1' } });
  assert.equal(r.status, 201);
  const { data } = await admin('/api/admin/users');
  const u = data.users.find((x) => x.email === email);
  assert.equal((await admin(`/api/admin/users/${u.id}/action`, { method: 'POST', body: { action: 'approve' } })).status, 200);
  assert.equal((await c('/api/auth/login', { method: 'POST', body: { email, password: 'Postor-Pass-1' } })).status, 200);
  return c;
}

let admin, ana, beto;

test('TOTP: genera y verifica códigos, rechaza reutilización', () => {
  const s = sec.generateTotpSecret();
  const code = sec.totpNow(s);
  const counter = sec.verifyTotp(s, code, 0);
  assert.ok(counter);
  assert.equal(sec.verifyTotp(s, code, counter), null, 'el mismo código no debe servir dos veces');
  assert.equal(sec.verifyTotp(s, '000000x', 0), null);
});

test('cabeceras de seguridad presentes', async () => {
  const res = await fetch(base + '/');
  assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('el administrador necesita contraseña + 2FA', async () => {
  admin = await loginAdmin();
  const me = await admin('/api/me');
  assert.equal(me.data.user.role, 'admin');
  const bad = await client()('/api/auth/login', { method: 'POST', body: { email: 'admin@test.com', password: 'Admin-Pass-123!', totp: '123456' } });
  assert.equal(bad.status, 401);
});

test('registro: contraseña débil rechazada, usuario queda pendiente', async () => {
  const c = client();
  const weak = await c('/api/auth/register', { method: 'POST', body: { email: 'x@test.com', name: 'X', password: 'corta' } });
  assert.equal(weak.status, 400);
  await c('/api/auth/register', { method: 'POST', body: { email: 'pend@test.com', name: 'Pendiente', password: 'Postor-Pass-1' } });
  await c('/api/auth/login', { method: 'POST', body: { email: 'pend@test.com', password: 'Postor-Pass-1' } });
  const me = await c('/api/me');
  assert.equal(me.data.user.status, 'pending');
});

test('CSRF: rechaza peticiones sin cabecera u origen distinto', async () => {
  const noHeader = await fetch(base + '/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: '{}',
  });
  assert.equal(noHeader.status, 403);
  const evil = await fetch(base + '/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-Requested-With': 'LicitApp' }, body: '{}',
  });
  assert.equal(evil.status, 403);
});

test('sin sesión no hay acceso; postor no accede al panel', async () => {
  assert.equal((await client()('/api/auctions')).status, 401);
  ana = await newBidder(admin, 'ana@test.com');
  beto = await newBidder(admin, 'beto@test.com');
  assert.equal((await ana('/api/admin/users')).status, 403);
  assert.equal((await ana('/api/admin/auctions', { method: 'POST', body: {} })).status, 403);
});

test('subasta abierta: reglas de puja e incremento mínimo', async () => {
  const r = await admin('/api/admin/auctions', { method: 'POST', body: {
    title: 'Camión 2020', mode: 'abierta', starting_price_cents: 100000, min_increment_cents: 5000,
    ends_at: Date.now() + 3600_000,
  } });
  assert.equal(r.status, 201);
  const id = r.data.id;
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 99999 } })).status, 409);
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 100000 } })).status, 201);
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 200000 } })).status, 409, 'no puede superarse a sí misma');
  const low = await beto(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 104999 } });
  assert.equal(low.status, 409);
  assert.equal(low.data.min_next_bid_cents, 105000);
  assert.equal((await beto(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 105000 } })).status, 201);
  assert.equal((await beto(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 1.5 } })).status, 400);
  assert.equal((await admin(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 999999 } })).status, 403);

  const view = (await ana(`/api/auctions/${id}`)).data.auction;
  assert.equal(view.current_price_cents, 105000);
  assert.equal(view.is_leader, false);
  assert.ok(view.bids.every((b) => !('name' in b)), 'los postores no ven nombres reales');

  assert.equal((await admin(`/api/admin/auctions/${id}/action`, { method: 'POST', body: { action: 'close' } })).status, 200);
  const closed = (await beto(`/api/auctions/${id}`)).data.auction;
  assert.equal(closed.status, 'cerrada');
  assert.equal(closed.i_won, true);
  assert.equal(closed.winning_bid_cents, 105000);
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 500000 } })).status, 409);
});

test('licitación sellada: montos ocultos hasta el cierre (incluso al admin)', async () => {
  const r = await admin('/api/admin/auctions', { method: 'POST', body: {
    title: 'Obra pública', mode: 'sellada', starting_price_cents: 1000000, ends_at: Date.now() + 3600_000,
  } });
  const id = r.data.id;
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 1500000 } })).status, 201);
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 1600000 } })).status, 409, 'solo una oferta');
  assert.equal((await beto(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 1200000 } })).status, 201);

  const asBeto = (await beto(`/api/auctions/${id}`)).data.auction;
  assert.equal(asBeto.current_price_cents, undefined);
  assert.equal(asBeto.bids, undefined);
  assert.equal(asBeto.my_best_bid_cents, 1200000);
  const asAdmin = (await admin(`/api/auctions/${id}`)).data.auction;
  assert.equal(asAdmin.current_price_cents, undefined);
  assert.equal(asAdmin.sealed_participants.length, 2);
  const audit = (await admin('/api/admin/audit')).data.entries.filter((e) => e.action === 'oferta.realizada' && e.details.auction_id === id);
  assert.ok(audit.every((e) => e.details.amount_cents === undefined && e.details.amount_commitment), 'la bitácora no revela montos sellados');

  await admin(`/api/admin/auctions/${id}/action`, { method: 'POST', body: { action: 'close' } });
  const after = (await beto(`/api/auctions/${id}`)).data.auction;
  assert.equal(after.winning_bid_cents, 1500000);
  assert.equal(after.bids.length, 2);
});

test('pausar/reanudar y anti-sniping', async () => {
  const r = await admin('/api/admin/auctions', { method: 'POST', body: {
    title: 'Lote final', mode: 'abierta', starting_price_cents: 1000, min_increment_cents: 100, ends_at: Date.now() + 90_000,
  } });
  const id = r.data.id;
  await admin(`/api/admin/auctions/${id}/action`, { method: 'POST', body: { action: 'pause' } });
  assert.equal((await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 1000 } })).status, 409);
  await admin(`/api/admin/auctions/${id}/action`, { method: 'POST', body: { action: 'resume' } });
  const bid = await ana(`/api/auctions/${id}/bids`, { method: 'POST', body: { amount_cents: 1000 } });
  assert.equal(bid.status, 201);
  assert.ok(bid.data.extended_to > Date.now() + 100_000, 'una oferta en los últimos 2 min extiende el cierre');
});

test('bloquear usuario cierra su sesión', async () => {
  const c = await newBidder(admin, 'carla@test.com');
  const { data } = await admin('/api/admin/users');
  const u = data.users.find((x) => x.email === 'carla@test.com');
  await admin(`/api/admin/users/${u.id}/action`, { method: 'POST', body: { action: 'block' } });
  assert.equal((await c('/api/auctions')).status, 401);
  assert.equal((await c('/api/auth/login', { method: 'POST', body: { email: 'carla@test.com', password: 'Postor-Pass-1' } })).status, 401);
});

test('bloqueo temporal tras 5 intentos fallidos', async () => {
  const c = client();
  await c('/api/auth/register', { method: 'POST', body: { email: 'dani@test.com', name: 'Dani', password: 'Postor-Pass-1' } });
  for (let i = 0; i < 5; i++) await c('/api/auth/login', { method: 'POST', body: { email: 'dani@test.com', password: 'mala' } });
  const r = await c('/api/auth/login', { method: 'POST', body: { email: 'dani@test.com', password: 'Postor-Pass-1' } });
  assert.equal(r.status, 401, 'aun con la contraseña correcta queda bloqueado temporalmente');
});

test('botón de pánico: requiere 2FA, pausa todo y expulsa postores', async () => {
  await admin('/api/admin/auctions', { method: 'POST', body: {
    title: 'Viva', mode: 'abierta', starting_price_cents: 1000, ends_at: Date.now() + 3600_000,
  } });
  assert.equal((await admin('/api/admin/panic', { method: 'POST', body: { totp: '000000' } })).status, 401);
  const r = await admin('/api/admin/panic', { method: 'POST', body: { totp: nextTotp() } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.ok(r.data.paused >= 1);
  assert.equal((await ana('/api/auctions')).status, 401);
  const reg = await client()('/api/auth/register', { method: 'POST', body: { email: 'nuevo@test.com', name: 'Nuevo', password: 'Postor-Pass-1' } });
  assert.equal(reg.status, 403, 'el registro queda cerrado');
});

test('bitácora encadenada detecta manipulación', async () => {
  assert.equal((await admin('/api/admin/audit/verify')).data.ok, true);
  ctx.db.prepare("UPDATE audit SET details = '{\"amount_cents\":1}' WHERE id = 3").run();
  const v = (await admin('/api/admin/audit/verify')).data;
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 3);
});
