'use strict';
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');
const sec = require('../src/security');

const TOKEN = 'token-de-prueba-1234567890';
const ctx = createApp({ dbPath: ':memory:', cookieSecure: false, setupToken: TOKEN });
let base;
after(() => ctx.close());

async function post(path, body, cookie) {
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: base, 'X-Requested-With': 'LicitApp', ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json(), cookie: res.headers.get('set-cookie')?.split(';')[0] };
}

test('asistente de configuración inicial crea el admin una sola vez', async () => {
  await new Promise((r) => ctx.server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${ctx.server.address().port}`;
  assert.equal((await (await fetch(base + '/api/setup/status')).json()).needed, true);
  assert.equal((await post('/api/setup/secret', { token: 'incorrecto', email: 'yo@test.com' })).status, 403);

  const s = await post('/api/setup/secret', { token: TOKEN, email: 'yo@test.com' });
  assert.equal(s.status, 200);
  assert.match(s.data.qr, /^data:image\/png;base64,/);
  const form = { token: TOKEN, email: 'yo@test.com', name: 'Yo', password: 'Admin-Pass-123!' };
  assert.equal((await post('/api/setup/complete', { ...form, totp: '000000' })).status, 400);
  const ok = await post('/api/setup/complete', { ...form, totp: sec.totpNow(s.data.secret) });
  assert.equal(ok.status, 201);

  const me = await (await fetch(base + '/api/me', { headers: { Cookie: ok.cookie } })).json();
  assert.equal(me.user.role, 'admin');
  assert.equal((await (await fetch(base + '/api/setup/status')).json()).needed, false);
  assert.equal((await post('/api/setup/secret', { token: TOKEN, email: 'otro@test.com' })).status, 404, 'deshabilitado tras crear admin');
});
