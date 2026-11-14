'use strict';
/**
 * Crea (o reinicia) la cuenta de administrador con doble verificación (TOTP).
 * Uso: npm run crear-admin
 * Escanea el código QR con Google Authenticator, Microsoft Authenticator, Authy, 1Password, etc.
 */
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const QRCode = require('qrcode');
const { openDb } = require('../src/db');
const sec = require('../src/security');

function ask(question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); else rl.output.write('*'); };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(answer.trim());
    });
  });
}

(async () => {
  const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'licitapp.db');
  fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  const db = openDb(dbPath);

  console.log('\n=== Crear administrador de LicitApp ===\n');
  const email = (await ask('Correo del administrador: ')).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Correo inválido');
  const name = (await ask('Nombre: ')) || 'Administrador';
  const pw = await ask('Contraseña (mín. 12 caracteres): ', { hidden: true });
  if (pw.length < 12) throw new Error('Para el administrador usa al menos 12 caracteres');
  const pwErr = sec.validatePasswordStrength(pw);
  if (pwErr) throw new Error(pwErr);
  const pw2 = await ask('Repite la contraseña: ', { hidden: true });
  if (pw !== pw2) throw new Error('Las contraseñas no coinciden');

  const secret = sec.generateTotpSecret();
  const hash = await sec.hashPassword(pw);
  const existing = db.prepare('SELECT id, role FROM users WHERE email = ?').get(email);
  if (existing) {
    db.prepare("UPDATE users SET name = ?, password_hash = ?, role = 'admin', status = 'active', totp_secret = ?, totp_last_counter = 0, failed_logins = 0, locked_until = 0 WHERE id = ?")
      .run(name, hash, secret, existing.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(existing.id);
  } else {
    db.prepare("INSERT INTO users (email, name, password_hash, role, status, totp_secret, created_at) VALUES (?, ?, ?, 'admin', 'active', ?, ?)")
      .run(email, name, hash, secret, Date.now());
  }

  const uri = sec.otpauthUri(secret, email);
  console.log('\nEscanea este código con tu app de autenticación en el celular:\n');
  console.log(await QRCode.toString(uri, { type: 'terminal', small: true }));
  console.log(`O ingresa la clave manualmente: ${secret.match(/.{1,4}/g).join(' ')}\n`);
  const code = await ask('Para confirmar, escribe el código de 6 dígitos que muestra tu app: ');
  if (sec.verifyTotp(secret, code, 0) === null) {
    console.log('\n✖ El código no coincide. Revisa la hora de tu celular y vuelve a ejecutar el comando.');
    process.exit(1);
  }
  console.log(`\n✔ Administrador listo: ${email}. Ya puedes iniciar sesión desde tu celular.\n`);
  db.close();
})().catch((err) => {
  console.error(`\n✖ ${err.message}`);
  process.exit(1);
});
