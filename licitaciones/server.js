'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createApp } = require('./src/app');

fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true, mode: 0o700 });

const { server, db, config } = createApp();
const port = Number(process.env.PORT) || 3000;
const host = process.env.HOST || '0.0.0.0';

const admins = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get().n;
if (admins === 0) {
  console.warn('\n⚠  No hay administrador. Créalo con:  npm run crear-admin\n');
}
if (!config.cookieSecure) {
  console.warn('⚠  COOKIE_SECURE=false: modo desarrollo. En producción usa HTTPS y COOKIE_SECURE=true.\n');
}

server.listen(port, host, () => {
  console.log(`LicitApp escuchando en http://${host}:${port}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log('Cerrando…');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
