'use strict';
const http = require('node:http');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const { Server } = require('socket.io');

const { openDb, tx, getAppSecret } = require('./db');
const { createAudit } = require('./audit');
const sec = require('./security');

const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;      // 2 h sin actividad
const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000; // 12 h máximo
const LOCK_AFTER_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const ANTI_SNIPING_MS = 2 * 60 * 1000;          // extiende 2 min si pujan al final
const MAX_AMOUNT_CENTS = 1e13;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k) out[k] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function str(v, field, { min = 1, max = 200 } = {}) {
  if (typeof v !== 'string') throw new HttpError(400, `Campo inválido: ${field}`);
  const s = v.trim();
  if (s.length < min || s.length > max) throw new HttpError(400, `Longitud inválida: ${field}`);
  return s;
}

function int(v, field, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(v) || v < min || v > max) throw new HttpError(400, `Valor inválido: ${field}`);
  return v;
}

function createApp(options = {}) {
  const config = {
    dbPath: options.dbPath ?? process.env.DB_PATH ?? path.join(__dirname, '..', 'data', 'licitapp.db'),
    cookieSecure: options.cookieSecure ?? process.env.COOKIE_SECURE !== 'false',
    trustProxy: options.trustProxy ?? (process.env.TRUST_PROXY || false),
    forceHttps: options.forceHttps ?? process.env.FORCE_HTTPS === 'true',
    allowedOrigins: (options.allowedOrigins ?? process.env.ALLOWED_ORIGINS ?? '')
      .split(',').map((s) => s.trim()).filter(Boolean),
  };
  const COOKIE_NAME = config.cookieSecure ? '__Host-sid' : 'sid';

  const db = options.db ?? openDb(config.dbPath);
  const appSecret = getAppSecret(db);
  let io; // se asigna más abajo
  const audit = createAudit(db, (entry) => {
    io?.to('admins').emit('audit:new', { id: entry.id, ts: entry.ts, action: entry.action });
  });

  const loginLimiter = sec.createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
  const registerLimiter = sec.createRateLimiter({ windowMs: 60 * 60 * 1000, max: 10 });
  const bidLimiter = sec.createRateLimiter({ windowMs: 60 * 1000, max: 30 });
  const apiLimiter = sec.createRateLimiter({ windowMs: 60 * 1000, max: 300 });

  const getSetting = (k, def) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? def;
  const setSetting = (k, v) =>
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, String(v));

  // ---------- Sesiones ----------
  function createSession(userId, req) {
    const token = sec.randomToken();
    const now = Date.now();
    db.prepare('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?').run(now, now - SESSION_IDLE_MS);
    db.prepare(
      'INSERT INTO sessions (id_hash, user_id, created_at, last_seen, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(sec.sha256(token), userId, now, now, now + SESSION_ABSOLUTE_MS, req.ip ?? null,
      String(req.headers['user-agent'] || '').slice(0, 200));
    return token;
  }

  function userFromToken(token) {
    if (!token || token.length > 100) return null;
    const now = Date.now();
    const row = db.prepare(`
      SELECT s.id_hash, s.last_seen, s.expires_at, u.id, u.email, u.name, u.role, u.status
      FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`).get(sec.sha256(token));
    if (!row) return null;
    if (row.expires_at < now || row.last_seen < now - SESSION_IDLE_MS || row.status === 'blocked') {
      db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(row.id_hash);
      return null;
    }
    if (now - row.last_seen > 60_000) {
      db.prepare('UPDATE sessions SET last_seen = ? WHERE id_hash = ?').run(now, row.id_hash);
    }
    return { id: row.id, email: row.email, name: row.name, role: row.role, status: row.status, sessionHash: row.id_hash };
  }

  function killUserSessions(userId) {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    io?.to(`user:${userId}`).disconnectSockets(true);
  }

  function setSessionCookie(res, token) {
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true, secure: config.cookieSecure, sameSite: 'strict', path: '/', maxAge: SESSION_ABSOLUTE_MS,
    });
  }

  // ---------- Vista de subastas (según quién mira) ----------
  function alias(auctionId, userId) {
    const h = crypto.createHmac('sha256', appSecret).update(`${auctionId}:${userId}`).digest('hex');
    return `Postor-${h.slice(0, 5).toUpperCase()}`;
  }

  function effectiveStatus(a, now = Date.now()) {
    if (a.status === 'activa' && a.starts_at > now) return 'programada';
    return a.status;
  }

  function auctionView(a, viewer, { withBids = false } = {}) {
    const now = Date.now();
    const isAdmin = viewer?.role === 'admin';
    const closed = a.status === 'cerrada';
    const stats = db.prepare(
      'SELECT COUNT(*) AS n, COUNT(DISTINCT user_id) AS bidders, MAX(amount_cents) AS top FROM bids WHERE auction_id = ?'
    ).get(a.id);
    const top = db.prepare(
      'SELECT user_id, amount_cents FROM bids WHERE auction_id = ? ORDER BY amount_cents DESC, id ASC LIMIT 1'
    ).get(a.id);

    const view = {
      id: a.id,
      title: a.title,
      description: a.description,
      mode: a.mode,
      status: effectiveStatus(a, now),
      starting_price_cents: a.starting_price_cents,
      min_increment_cents: a.min_increment_cents,
      starts_at: a.starts_at,
      ends_at: a.status === 'pausada' ? null : a.ends_at,
      paused_remaining_ms: a.paused_remaining_ms,
      bid_count: stats.n,
      bidder_count: stats.bidders,
      server_time: now,
    };

    const revealAmounts = a.mode === 'abierta' || closed;
    if (revealAmounts && top) {
      view.current_price_cents = top.amount_cents;
      view.leader = alias(a.id, top.user_id);
      view.is_leader = viewer ? top.user_id === viewer.id : false;
    }
    if (a.mode === 'abierta') {
      view.min_next_bid_cents = top ? top.amount_cents + a.min_increment_cents : a.starting_price_cents;
    } else {
      view.min_next_bid_cents = a.starting_price_cents;
    }
    if (viewer && !isAdmin) {
      const mine = db.prepare(
        'SELECT MAX(amount_cents) AS amount FROM bids WHERE auction_id = ? AND user_id = ?'
      ).get(a.id, viewer.id);
      view.my_best_bid_cents = mine.amount ?? null;
      view.my_alias = alias(a.id, viewer.id);
    }
    if (closed) {
      view.winner = a.winner_user_id ? alias(a.id, a.winner_user_id) : null;
      view.winning_bid_cents = a.winning_bid_cents;
      view.i_won = viewer ? a.winner_user_id === viewer.id : false;
      if (isAdmin && a.winner_user_id) {
        const w = db.prepare('SELECT name, email FROM users WHERE id = ?').get(a.winner_user_id);
        view.winner_contact = w;
      }
    }

    if (withBids) {
      if (revealAmounts) {
        view.bids = db.prepare(`
          SELECT b.id, b.user_id, b.amount_cents, b.created_at, u.name
          FROM bids b JOIN users u ON u.id = b.user_id
          WHERE b.auction_id = ? ORDER BY b.amount_cents DESC, b.id ASC LIMIT 50`).all(a.id)
          .map((b) => ({
            id: b.id,
            alias: alias(a.id, b.user_id),
            amount_cents: b.amount_cents,
            created_at: b.created_at,
            mine: viewer ? b.user_id === viewer.id : false,
            ...(isAdmin ? { name: b.name } : {}),
          }));
      } else if (isAdmin) {
        // Licitación sellada en curso: ni el administrador ve los montos.
        view.sealed_participants = db.prepare(`
          SELECT DISTINCT u.name FROM bids b JOIN users u ON u.id = b.user_id WHERE b.auction_id = ?`).all(a.id)
          .map((r) => r.name);
      }
    }
    return view;
  }

  function notifyAuction(auctionId) {
    io?.emit('auction:update', { id: auctionId });
  }

  // ---------- Cierre de subastas ----------
  function closeAuction(auctionId, actorId, reason) {
    const result = tx(db, () => {
      const a = db.prepare('SELECT * FROM auctions WHERE id = ?').get(auctionId);
      if (!a || !['activa', 'pausada'].includes(a.status)) return null;
      const top = db.prepare(
        'SELECT user_id, amount_cents FROM bids WHERE auction_id = ? ORDER BY amount_cents DESC, id ASC LIMIT 1'
      ).get(auctionId);
      db.prepare(`UPDATE auctions SET status = 'cerrada', ends_at = MIN(ends_at, ?), paused_remaining_ms = NULL,
        winner_user_id = ?, winning_bid_cents = ? WHERE id = ?`)
        .run(Date.now(), top?.user_id ?? null, top?.amount_cents ?? null, auctionId);
      audit.log(actorId, 'subasta.cerrada', {
        auction_id: auctionId, reason, winner_user_id: top?.user_id ?? null, winning_bid_cents: top?.amount_cents ?? null,
      });
      return { winner: top?.user_id ?? null };
    });
    if (result) {
      notifyAuction(auctionId);
      io?.to('admins').emit('admin:alert', { type: 'cerrada', auction_id: auctionId });
    }
    return result;
  }

  const closer = setInterval(() => {
    const due = db.prepare("SELECT id FROM auctions WHERE status = 'activa' AND ends_at <= ?").all(Date.now());
    for (const { id } of due) closeAuction(id, null, 'tiempo_terminado');
  }, 1000);
  closer.unref();

  // ---------- Express ----------
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  if (config.forceHttps) {
    app.use((req, res, next) => (req.secure ? next() : res.redirect(301, `https://${req.headers.host}${req.originalUrl}`)));
  }

  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        manifestSrc: ["'self'"],
        workerSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: config.cookieSecure ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
  }));
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  });

  function isAllowedOrigin(origin, host) {
    if (!origin) return false;
    if (config.allowedOrigins.includes(origin)) return true;
    try { return new URL(origin).host === host; } catch { return false; }
  }

  const api = express.Router();
  api.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const rl = apiLimiter(req.ip);
    if (!rl.allowed) throw new HttpError(429, 'Demasiadas peticiones, espera un momento');
    // Protección CSRF: SameSite=Strict + Origin del mismo sitio + cabecera personalizada.
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      if (req.get('X-Requested-With') !== 'LicitApp' || !isAllowedOrigin(req.get('Origin'), req.get('host'))) {
        throw new HttpError(403, 'Petición rechazada (origen no válido)');
      }
      if (!req.is('application/json')) throw new HttpError(415, 'Se requiere JSON');
    }
    req.user = userFromToken(parseCookies(req.headers.cookie)[COOKIE_NAME]);
    next();
  });
  api.use(express.json({ limit: '10kb', strict: true }));

  const requireUser = (req, res, next) => {
    if (!req.user) throw new HttpError(401, 'Inicia sesión');
    next();
  };
  const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') throw new HttpError(403, 'Solo el administrador');
    next();
  };
  const body = (req) => (req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {});

  // ----- Autenticación -----
  api.post('/auth/register', async (req, res) => {
    if (!registerLimiter(req.ip).allowed) throw new HttpError(429, 'Demasiados registros desde esta red');
    if (getSetting('registrations_open', '1') !== '1') throw new HttpError(403, 'El registro está cerrado');
    const b = body(req);
    const email = str(b.email, 'email', { max: 254 }).toLowerCase();
    if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Correo inválido');
    const name = str(b.name, 'nombre', { min: 2, max: 80 });
    const pwErr = sec.validatePasswordStrength(b.password);
    if (pwErr) throw new HttpError(400, pwErr);
    const hash = await sec.hashPassword(b.password);
    const exists = db.prepare('SELECT 1 FROM users WHERE email = ?').get(email);
    if (exists) {
      // Respuesta idéntica para no revelar qué correos están registrados.
      return res.status(201).json({ ok: true, message: 'Registro recibido. El administrador debe aprobar tu cuenta.' });
    }
    const r = db.prepare(
      "INSERT INTO users (email, name, password_hash, role, status, created_at) VALUES (?, ?, ?, 'bidder', 'pending', ?)"
    ).run(email, name, hash, Date.now());
    audit.log(Number(r.lastInsertRowid), 'usuario.registrado', { email });
    io?.to('admins').emit('admin:alert', { type: 'registro', name });
    res.status(201).json({ ok: true, message: 'Registro recibido. El administrador debe aprobar tu cuenta.' });
  });

  api.post('/auth/login', async (req, res) => {
    const b = body(req);
    const email = typeof b.email === 'string' ? b.email.trim().toLowerCase().slice(0, 254) : '';
    const password = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
    const rl = loginLimiter(`${req.ip}`);
    const rlEmail = loginLimiter(`email:${email}`);
    if (!rl.allowed || !rlEmail.allowed) throw new HttpError(429, 'Demasiados intentos. Prueba más tarde.');

    const generic = new HttpError(401, 'Credenciales inválidas o cuenta bloqueada temporalmente');
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      await sec.verifyPassword(password, await sec.dummyHash());
      throw generic;
    }
    const now = Date.now();
    if (user.locked_until > now || user.status === 'blocked') throw generic;

    const fail = (why) => {
      const fails = user.failed_logins + 1;
      if (fails >= LOCK_AFTER_FAILS) {
        db.prepare('UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?').run(now + LOCK_MS, user.id);
        audit.log(user.id, 'login.cuenta_bloqueada_temporalmente', { ip: req.ip });
        if (user.role === 'admin') io?.to('admins').emit('admin:alert', { type: 'bloqueo_admin' });
      } else {
        db.prepare('UPDATE users SET failed_logins = ? WHERE id = ?').run(fails, user.id);
      }
      audit.log(user.id, 'login.fallido', { ip: req.ip, motivo: why });
      return generic;
    };

    if (!(await sec.verifyPassword(password, user.password_hash))) throw fail('contraseña');

    if (user.role === 'admin') {
      if (!user.totp_secret) throw new HttpError(500, 'El administrador no tiene 2FA configurado');
      if (!b.totp) throw new HttpError(401, 'Ingresa el código de tu app de autenticación', { totp_required: true });
      const counter = sec.verifyTotp(user.totp_secret, b.totp, user.totp_last_counter);
      if (counter === null) throw fail('codigo_2fa');
      db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?').run(counter, user.id);
    }

    db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(user.id);
    const token = createSession(user.id, req);
    setSessionCookie(res, token);
    audit.log(user.id, 'login.exitoso', { ip: req.ip, ua: String(req.headers['user-agent'] || '').slice(0, 120) });
    if (user.role === 'admin') io?.to('admins').emit('admin:alert', { type: 'login_admin', ip: req.ip });
    res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } });
  });

  api.post('/auth/logout', (req, res) => {
    if (req.user) {
      db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(req.user.sessionHash);
      audit.log(req.user.id, 'logout', {});
    }
    res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: config.cookieSecure, sameSite: 'strict', path: '/' });
    res.json({ ok: true });
  });

  // ----- Configuración inicial desde el navegador (solo mientras no exista administrador) -----
  // Requiere SETUP_TOKEN (mín. 16 caracteres) definido en el servidor. Una vez creado el
  // administrador, estas rutas dejan de funcionar para siempre.
  const setupLimiter = sec.createRateLimiter({ windowMs: 15 * 60 * 1000, max: 15 });
  let pendingSetupSecret = null;
  const setupToken = options.setupToken ?? process.env.SETUP_TOKEN ?? '';
  const adminExists = () => !!db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
  function checkSetup(req) {
    if (adminExists() || setupToken.length < 16) throw new HttpError(404, 'Ruta no encontrada');
    if (!setupLimiter(req.ip).allowed) throw new HttpError(429, 'Demasiados intentos. Prueba más tarde.');
    const given = Buffer.from(String(body(req).token || ''));
    const expected = Buffer.from(setupToken);
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
      audit.log(null, 'setup.token_invalido', { ip: req.ip });
      throw new HttpError(403, 'Código de configuración incorrecto');
    }
  }

  api.get('/setup/status', (req, res) => {
    res.json({ needed: !adminExists() && setupToken.length >= 16 });
  });

  api.post('/setup/secret', async (req, res) => {
    checkSetup(req);
    const email = str(body(req).email, 'email', { max: 254 }).toLowerCase();
    if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Correo inválido');
    pendingSetupSecret = sec.generateTotpSecret();
    const uri = sec.otpauthUri(pendingSetupSecret, email);
    const qr = await require('qrcode').toDataURL(uri, { margin: 1, width: 240 });
    res.json({ secret: pendingSetupSecret, uri, qr });
  });

  api.post('/setup/complete', async (req, res) => {
    checkSetup(req);
    const b = body(req);
    if (!pendingSetupSecret) throw new HttpError(409, 'Primero genera el código 2FA');
    const email = str(b.email, 'email', { max: 254 }).toLowerCase();
    if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Correo inválido');
    const name = str(b.name, 'nombre', { min: 2, max: 80 });
    if (typeof b.password !== 'string' || b.password.length < 12) {
      throw new HttpError(400, 'Para el administrador usa al menos 12 caracteres');
    }
    const pwErr = sec.validatePasswordStrength(b.password);
    if (pwErr) throw new HttpError(400, pwErr);
    const counter = sec.verifyTotp(pendingSetupSecret, b.totp, 0);
    if (counter === null) throw new HttpError(400, 'El código de 6 dígitos no coincide. Revisa la hora del celular.');
    const hash = await sec.hashPassword(b.password);
    const userId = tx(db, () => {
      if (adminExists()) throw new HttpError(409, 'El administrador ya existe');
      const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (existing) {
        db.prepare(`UPDATE users SET name = ?, password_hash = ?, role = 'admin', status = 'active', totp_secret = ?,
          totp_last_counter = ?, failed_logins = 0, locked_until = 0 WHERE id = ?`)
          .run(name, hash, pendingSetupSecret, counter, existing.id);
        db.prepare('DELETE FROM sessions WHERE user_id = ?').run(existing.id);
        return existing.id;
      }
      const r = db.prepare(`INSERT INTO users (email, name, password_hash, role, status, totp_secret, totp_last_counter, created_at)
        VALUES (?, ?, ?, 'admin', 'active', ?, ?, ?)`).run(email, name, hash, pendingSetupSecret, counter, Date.now());
      return Number(r.lastInsertRowid);
    });
    pendingSetupSecret = null;
    audit.log(userId, 'setup.admin_creado', { email, ip: req.ip });
    setSessionCookie(res, createSession(userId, req));
    res.status(201).json({ ok: true });
  });

  api.get('/me', (req, res) => {
    if (!req.user) return res.json({ user: null });
    const { sessionHash, ...user } = req.user;
    res.json({ user });
  });

  // ----- Subastas (postores) -----
  api.get('/auctions', requireUser, (req, res) => {
    const rows = req.user.role === 'admin'
      ? db.prepare('SELECT * FROM auctions ORDER BY id DESC LIMIT 200').all()
      : db.prepare("SELECT * FROM auctions WHERE status != 'borrador' ORDER BY id DESC LIMIT 200").all();
    res.json({ auctions: rows.map((a) => auctionView(a, req.user)) });
  });

  api.get('/auctions/:id', requireUser, (req, res) => {
    const id = Number(req.params.id);
    const a = Number.isSafeInteger(id) ? db.prepare('SELECT * FROM auctions WHERE id = ?').get(id) : null;
    if (!a || (a.status === 'borrador' && req.user.role !== 'admin')) throw new HttpError(404, 'No existe');
    res.json({ auction: auctionView(a, req.user, { withBids: true }) });
  });

  api.post('/auctions/:id/bids', requireUser, (req, res) => {
    if (req.user.role === 'admin') throw new HttpError(403, 'El administrador no puede pujar');
    if (req.user.status !== 'active') throw new HttpError(403, 'Tu cuenta aún no está aprobada');
    if (!bidLimiter(`u:${req.user.id}`).allowed) throw new HttpError(429, 'Vas muy rápido, espera unos segundos');
    const id = Number(req.params.id);
    const amount = int(body(req).amount_cents, 'monto', { min: 1, max: MAX_AMOUNT_CENTS });

    const outcome = tx(db, () => {
      const now = Date.now();
      const a = Number.isSafeInteger(id) ? db.prepare('SELECT * FROM auctions WHERE id = ?').get(id) : null;
      if (!a || a.status === 'borrador') throw new HttpError(404, 'No existe');
      if (a.status !== 'activa' || a.starts_at > now || a.ends_at <= now) {
        throw new HttpError(409, 'La subasta no está recibiendo ofertas');
      }
      let extendedTo = null;
      if (a.mode === 'abierta') {
        const top = db.prepare('SELECT user_id, amount_cents FROM bids WHERE auction_id = ? ORDER BY amount_cents DESC, id ASC LIMIT 1').get(id);
        const min = top ? top.amount_cents + a.min_increment_cents : a.starting_price_cents;
        if (amount < min) throw new HttpError(409, 'La oferta es menor que el mínimo permitido', { min_next_bid_cents: min });
        if (top && top.user_id === req.user.id) throw new HttpError(409, 'Ya vas ganando esta subasta');
        if (a.ends_at - now < ANTI_SNIPING_MS) {
          extendedTo = now + ANTI_SNIPING_MS;
          db.prepare('UPDATE auctions SET ends_at = ? WHERE id = ?').run(extendedTo, id);
        }
      } else {
        if (amount < a.starting_price_cents) {
          throw new HttpError(409, 'La oferta es menor que el precio base', { min_next_bid_cents: a.starting_price_cents });
        }
        const already = db.prepare('SELECT 1 FROM bids WHERE auction_id = ? AND user_id = ?').get(id, req.user.id);
        if (already) throw new HttpError(409, 'En licitación sellada solo se permite una oferta por participante');
      }
      const r = db.prepare('INSERT INTO bids (auction_id, user_id, amount_cents, created_at, ip) VALUES (?, ?, ?, ?, ?)')
        .run(id, req.user.id, amount, now, req.ip ?? null);
      audit.log(req.user.id, 'oferta.realizada', {
        auction_id: id, bid_id: Number(r.lastInsertRowid),
        // En sellada el monto queda en la bitácora como hash (compromiso), no en claro.
        ...(a.mode === 'abierta' ? { amount_cents: amount } : { amount_commitment: sec.sha256(`${appSecret}:${r.lastInsertRowid}:${amount}`) }),
        ...(extendedTo ? { extended_to: extendedTo } : {}),
      });
      return { bidId: Number(r.lastInsertRowid), extendedTo, mode: a.mode, title: a.title };
    });

    notifyAuction(id);
    io?.to('admins').emit('admin:alert', {
      type: 'oferta', auction_id: id, title: outcome.title,
      ...(outcome.mode === 'abierta' ? { amount_cents: amount } : {}),
    });
    res.status(201).json({ ok: true, bid_id: outcome.bidId, extended_to: outcome.extendedTo });
  });

  // ----- Panel de administración -----
  const admin = express.Router();
  admin.use(requireAdmin);

  admin.get('/dashboard', (req, res) => {
    const c = (sql, ...p) => db.prepare(sql).get(...p).n;
    res.json({
      pending_users: c("SELECT COUNT(*) AS n FROM users WHERE status = 'pending'"),
      active_users: c("SELECT COUNT(*) AS n FROM users WHERE status = 'active' AND role = 'bidder'"),
      live_auctions: c("SELECT COUNT(*) AS n FROM auctions WHERE status = 'activa' AND starts_at <= ?", Date.now()),
      bids_24h: c('SELECT COUNT(*) AS n FROM bids WHERE created_at > ?', Date.now() - 86400000),
      online_sockets: io ? io.engine.clientsCount : 0,
      registrations_open: getSetting('registrations_open', '1') === '1',
    });
  });

  admin.post('/auctions', (req, res) => {
    const b = body(req);
    const now = Date.now();
    const title = str(b.title, 'título', { min: 3, max: 120 });
    const description = typeof b.description === 'string' ? b.description.trim().slice(0, 2000) : '';
    if (!['abierta', 'sellada'].includes(b.mode)) throw new HttpError(400, 'Modo inválido');
    const starting = int(b.starting_price_cents, 'precio base', { min: 1, max: MAX_AMOUNT_CENTS });
    const increment = int(b.min_increment_cents ?? 100, 'incremento mínimo', { min: 1, max: MAX_AMOUNT_CENTS });
    const startsAt = b.starts_at == null ? now : int(b.starts_at, 'inicio', { min: now - 60_000, max: now + 365 * 86400000 });
    const endsAt = int(b.ends_at, 'cierre', { min: Math.max(startsAt, now) + 60_000, max: startsAt + 90 * 86400000 });
    const status = b.publish === false ? 'borrador' : 'activa';
    const r = db.prepare(`INSERT INTO auctions (title, description, mode, starting_price_cents, min_increment_cents,
      status, starts_at, ends_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(title, description, b.mode, starting, increment, status, startsAt, endsAt, req.user.id, now);
    const id = Number(r.lastInsertRowid);
    audit.log(req.user.id, 'subasta.creada', { auction_id: id, title, mode: b.mode, status, starting, increment, startsAt, endsAt });
    notifyAuction(id);
    res.status(201).json({ ok: true, id });
  });

  admin.post('/auctions/:id/action', (req, res) => {
    const id = Number(req.params.id);
    const action = body(req).action;
    const now = Date.now();
    const a = Number.isSafeInteger(id) ? db.prepare('SELECT * FROM auctions WHERE id = ?').get(id) : null;
    if (!a) throw new HttpError(404, 'No existe');
    const bad = () => new HttpError(409, `No se puede "${action}" una subasta en estado ${a.status}`);

    switch (action) {
      case 'publish':
        if (a.status !== 'borrador') throw bad();
        if (a.ends_at <= now + 60_000) throw new HttpError(409, 'La fecha de cierre ya pasó; crea una nueva');
        db.prepare("UPDATE auctions SET status = 'activa' WHERE id = ?").run(id);
        break;
      case 'pause':
        if (a.status !== 'activa') throw bad();
        db.prepare("UPDATE auctions SET status = 'pausada', paused_remaining_ms = ? WHERE id = ?")
          .run(Math.max(a.ends_at - Math.max(now, a.starts_at), 60_000), id);
        break;
      case 'resume': {
        if (a.status !== 'pausada') throw bad();
        const startsAt = Math.max(a.starts_at, now);
        db.prepare("UPDATE auctions SET status = 'activa', starts_at = ?, ends_at = ?, paused_remaining_ms = NULL WHERE id = ?")
          .run(startsAt, startsAt + a.paused_remaining_ms, id);
        break;
      }
      case 'close':
        if (!['activa', 'pausada'].includes(a.status)) throw bad();
        closeAuction(id, req.user.id, 'cierre_manual');
        return res.json({ ok: true });
      case 'cancel':
        if (['cerrada', 'cancelada'].includes(a.status)) throw bad();
        db.prepare("UPDATE auctions SET status = 'cancelada', paused_remaining_ms = NULL WHERE id = ?").run(id);
        break;
      default:
        throw new HttpError(400, 'Acción inválida');
    }
    audit.log(req.user.id, `subasta.${action}`, { auction_id: id });
    notifyAuction(id);
    res.json({ ok: true });
  });

  admin.get('/users', (req, res) => {
    const users = db.prepare(`
      SELECT u.id, u.email, u.name, u.role, u.status, u.created_at, u.locked_until,
        (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ?) AS sessions,
        (SELECT COUNT(*) FROM bids b WHERE b.user_id = u.id) AS bids
      FROM users u ORDER BY CASE u.status WHEN 'pending' THEN 0 ELSE 1 END, u.id DESC LIMIT 500`).all(Date.now());
    res.json({ users });
  });

  admin.post('/users/:id/action', (req, res) => {
    const id = Number(req.params.id);
    const action = body(req).action;
    const u = Number.isSafeInteger(id) ? db.prepare('SELECT * FROM users WHERE id = ?').get(id) : null;
    if (!u) throw new HttpError(404, 'No existe');
    if (u.role === 'admin') throw new HttpError(403, 'No se puede modificar a un administrador desde aquí');
    switch (action) {
      case 'approve':
        if (u.status !== 'pending') throw new HttpError(409, 'El usuario no está pendiente');
        db.prepare("UPDATE users SET status = 'active' WHERE id = ?").run(id);
        io?.to(`user:${id}`).emit('me:update');
        break;
      case 'block':
        db.prepare("UPDATE users SET status = 'blocked' WHERE id = ?").run(id);
        killUserSessions(id);
        break;
      case 'unblock':
        if (u.status !== 'blocked') throw new HttpError(409, 'El usuario no está bloqueado');
        db.prepare("UPDATE users SET status = 'active', failed_logins = 0, locked_until = 0 WHERE id = ?").run(id);
        break;
      case 'logout':
        killUserSessions(id);
        break;
      default:
        throw new HttpError(400, 'Acción inválida');
    }
    audit.log(req.user.id, `usuario.${action}`, { user_id: id, email: u.email });
    res.json({ ok: true });
  });

  admin.post('/settings', (req, res) => {
    const b = body(req);
    if (typeof b.registrations_open !== 'boolean') throw new HttpError(400, 'Valor inválido');
    setSetting('registrations_open', b.registrations_open ? '1' : '0');
    audit.log(req.user.id, 'ajustes.registro', { abierto: b.registrations_open });
    res.json({ ok: true });
  });

  // Botón de pánico: pausa todo y expulsa a todos los postores. Requiere código 2FA fresco.
  admin.post('/panic', (req, res) => {
    const u = db.prepare('SELECT totp_secret, totp_last_counter FROM users WHERE id = ?').get(req.user.id);
    const counter = sec.verifyTotp(u.totp_secret, body(req).totp, u.totp_last_counter);
    if (counter === null) throw new HttpError(401, 'Código 2FA inválido');
    db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?').run(counter, req.user.id);
    const now = Date.now();
    const paused = tx(db, () => {
      const live = db.prepare("SELECT id, starts_at, ends_at FROM auctions WHERE status = 'activa'").all();
      for (const a of live) {
        db.prepare("UPDATE auctions SET status = 'pausada', paused_remaining_ms = ? WHERE id = ?")
          .run(Math.max(a.ends_at - Math.max(now, a.starts_at), 60_000), a.id);
      }
      db.prepare("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role = 'bidder')").run();
      setSetting('registrations_open', '0');
      return live.map((a) => a.id);
    });
    for (const s of io ? io.of('/').sockets.values() : []) if (s.data.user?.role !== 'admin') s.disconnect(true);
    for (const id of paused) notifyAuction(id);
    audit.log(req.user.id, 'panico.activado', { subastas_pausadas: paused, ip: req.ip });
    res.json({ ok: true, paused: paused.length });
  });

  admin.get('/audit', (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
    const rows = db.prepare(`SELECT a.id, a.ts, a.actor_id, u.name AS actor, a.action, a.details, a.hash
      FROM audit a LEFT JOIN users u ON u.id = a.actor_id ORDER BY a.id DESC LIMIT ?`).all(limit);
    res.json({ entries: rows.map((r) => ({ ...r, details: JSON.parse(r.details) })) });
  });

  admin.get('/audit/verify', (req, res) => res.json(audit.verify()));

  api.use('/admin', admin);
  api.use((req, res) => { throw new HttpError(404, 'Ruta no encontrada'); });

  app.use('/api', api);
  app.use(express.static(path.join(__dirname, '..', 'public'), {
    setHeaders(res, file) {
      if (file.endsWith('sw.js')) res.setHeader('Cache-Control', 'no-cache');
    },
  }));

  // Manejo de errores: nunca se filtran trazas al cliente.
  app.use((err, req, res, next) => {
    if (err instanceof HttpError) {
      return res.status(err.status).json({ error: err.message, ...err.extra });
    }
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
      return res.status(400).json({ error: 'Cuerpo de la petición inválido' });
    }
    console.error(err);
    res.status(500).json({ error: 'Error interno' });
  });

  // ---------- Tiempo real (Socket.IO) ----------
  const server = http.createServer(app);
  io = new Server(server, {
    serveClient: true,
    maxHttpBufferSize: 1e4,
    allowRequest(req, cb) {
      cb(null, isAllowedOrigin(req.headers.origin, req.headers.host));
    },
  });
  io.use((socket, next) => {
    const user = userFromToken(parseCookies(socket.handshake.headers.cookie)[COOKIE_NAME]);
    if (!user) return next(new Error('no autorizado'));
    socket.data.user = user;
    next();
  });
  io.on('connection', (socket) => {
    const u = socket.data.user;
    socket.join(`user:${u.id}`);
    if (u.role === 'admin') socket.join('admins');
    // El cliente no envía comandos por socket: todas las acciones pasan por la API validada.
  });

  function close() {
    clearInterval(closer);
    io.close(); // también cierra el servidor HTTP
    if (!options.db) db.close();
  }

  return { app, server, io, db, audit, close, config };
}

module.exports = { createApp };
