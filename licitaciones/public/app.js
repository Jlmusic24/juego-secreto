'use strict';
(() => {
  // ---------- Utilidades ----------
  const $view = document.getElementById('view');
  const $nav = document.getElementById('nav');
  const $conn = document.getElementById('conn');
  const $toasts = document.getElementById('toasts');

  /** Crea elementos de forma segura (solo textContent, nunca innerHTML con datos). */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (v === true) node.setAttribute(k, '');
      else node.setAttribute(k, String(v));
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  const money = (cents) =>
    cents == null ? '—' : '$' + (cents / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

  function parseMoney(input) {
    const clean = String(input).trim().replace(/\s/g, '').replace(/[$]/g, '');
    // Acepta "1.234,56", "1,234.56", "1234.5" o "1234"
    let normalized = clean;
    if (/,\d{1,2}$/.test(clean)) normalized = clean.replace(/\./g, '').replace(',', '.');
    else normalized = clean.replace(/,/g, '');
    if (!/^\d+(\.\d{1,2})?$/.test(normalized)) return null;
    return Math.round(Number(normalized) * 100);
  }

  const fmtDate = (ms) => new Date(ms).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });

  function fmtRemaining(ms) {
    if (ms <= 0) return '00:00';
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return d > 0 ? `${d}d ${pad(h)}:${pad(m)}:${pad(sec)}` : h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
  }

  function toast(msg, type = 'info') {
    const t = el('div', { class: `toast ${type}`, role: 'status' }, msg);
    $toasts.append(t);
    setTimeout(() => t.remove(), 3500);
    while ($toasts.childElementCount > 2) $toasts.firstChild.remove();
  }

  async function api(path, { method = 'GET', body } = {}) {
    const res = await fetch(`/api${path}`, {
      method,
      credentials: 'same-origin',
      headers: body ? { 'Content-Type': 'application/json', 'X-Requested-With': 'LicitApp' } : { 'X-Requested-With': 'LicitApp' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && state.user && !path.startsWith('/auth/')) {
      state.user = null;
      disconnectSocket();
      location.hash = '#/login';
    }
    if (!res.ok) {
      const err = new Error(data.error || `Error ${res.status}`);
      err.data = data;
      err.status = res.status;
      throw err;
    }
    return data;
  }

  const STATUS_LABEL = {
    programada: 'Programada', activa: 'En vivo', pausada: 'Pausada', cerrada: 'Cerrada', cancelada: 'Cancelada', borrador: 'Borrador',
  };
  const badge = (status) => el('span', { class: `badge st-${status}` }, STATUS_LABEL[status] || status);

  // ---------- Estado y tiempo real ----------
  const state = { user: null, socket: null, clockOffset: 0, timers: [], currentAuctionId: null };

  function connectSocket() {
    if (state.socket || typeof io !== 'function') return;
    const s = io({ withCredentials: true, transports: ['websocket', 'polling'] });
    state.socket = s;
    s.on('connect', () => { $conn.className = 'conn on'; $conn.title = 'Conectado en tiempo real'; });
    s.on('disconnect', () => { $conn.className = 'conn off'; $conn.title = 'Sin conexión en tiempo real'; });
    s.on('connect_error', () => { $conn.className = 'conn off'; });
    s.on('auction:update', ({ id }) => {
      if (state.currentAuctionId === id) renderAuction(id, { silent: true });
      else if (location.hash === '#/' || location.hash === '') renderList({ silent: true });
      else if (location.hash.startsWith('#/admin')) refreshAdmin();
    });
    s.on('me:update', async () => {
      await loadMe();
      toast('¡Tu cuenta fue aprobada! Ya puedes ofertar.', 'ok');
      route();
    });
    s.on('admin:alert', (a) => {
      const msg = {
        registro: `Nuevo registro: ${a.name}`,
        oferta: `Nueva oferta en "${a.title}"${a.amount_cents ? `: ${money(a.amount_cents)}` : ''}`,
        cerrada: `Subasta #${a.auction_id} cerrada`,
        login_admin: `Inicio de sesión de administrador desde ${a.ip}`,
        bloqueo_admin: '⚠ Bloqueo temporal por intentos fallidos en una cuenta de administrador',
      }[a.type];
      if (msg) {
        toast(msg, a.type === 'bloqueo_admin' ? 'error' : 'info');
        notifyDevice(msg);
      }
      if (location.hash.startsWith('#/admin')) refreshAdmin();
    });
  }

  function disconnectSocket() {
    state.socket?.disconnect();
    state.socket = null;
    $conn.className = 'conn';
  }

  function notifyDevice(msg) {
    if (navigator.vibrate) navigator.vibrate(120);
    if (document.hidden && 'Notification' in window && Notification.permission === 'granted') {
      navigator.serviceWorker?.ready.then((reg) => reg.showNotification('LicitApp', { body: msg, icon: '/icon.svg' }))
        .catch(() => {});
    }
  }

  function clearTimers() {
    state.timers.forEach(clearInterval);
    state.timers = [];
  }

  function countdown(node, endsAt, prefix = '') {
    const tick = () => {
      const remaining = endsAt - (Date.now() + state.clockOffset);
      node.textContent = prefix + fmtRemaining(remaining);
      node.classList.toggle('urgent', remaining > 0 && remaining < 120000);
    };
    tick();
    state.timers.push(setInterval(tick, 1000));
  }

  async function loadMe() {
    const { user } = await api('/me');
    state.user = user;
    return user;
  }

  function renderNav() {
    $nav.replaceChildren();
    if (!state.user) return;
    $nav.append(...[
      el('a', { href: '#/' }, 'Subastas'),
      state.user.role === 'admin' ? el('a', { href: '#/admin' }, 'Panel') : null,
      el('button', { class: 'link', onclick: logout }, 'Salir'),
    ].filter(Boolean));
  }

  async function logout() {
    await api('/auth/logout', { method: 'POST', body: {} }).catch(() => {});
    state.user = null;
    disconnectSocket();
    location.hash = '#/login';
  }

  // ---------- Vistas: acceso ----------
  function renderLogin() {
    let needTotp = false;
    const msg = el('p', { class: 'msg' });
    const totpWrap = el('label', { hidden: true }, 'Código de verificación (6 dígitos)',
      el('input', { name: 'totp', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9]{6}', maxlength: 6 }));
    const form = el('form', { class: 'card form', novalidate: true },
      el('h1', {}, 'Iniciar sesión'),
      el('label', {}, 'Correo', el('input', { name: 'email', type: 'email', autocomplete: 'username', required: true })),
      el('label', {}, 'Contraseña', el('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true })),
      totpWrap,
      el('button', { class: 'btn primary', type: 'submit' }, 'Entrar'),
      msg,
      el('p', { class: 'muted' }, '¿No tienes cuenta? ', el('a', { href: '#/registro' }, 'Regístrate')),
    );
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      msg.textContent = '';
      const f = new FormData(form);
      const btn = form.querySelector('button');
      btn.disabled = true;
      try {
        await api('/auth/login', {
          method: 'POST',
          body: { email: f.get('email'), password: f.get('password'), ...(needTotp ? { totp: f.get('totp') } : {}) },
        });
        await loadMe();
        connectSocket();
        location.hash = state.user.role === 'admin' ? '#/admin' : '#/';
      } catch (err) {
        if (err.data?.totp_required) {
          needTotp = true;
          totpWrap.hidden = false;
          totpWrap.querySelector('input').focus();
          msg.textContent = 'Abre tu app de autenticación e ingresa el código.';
        } else {
          msg.textContent = err.message;
          msg.className = 'msg error';
        }
      } finally {
        btn.disabled = false;
      }
    });
    $view.replaceChildren(form);
  }

  function renderRegister() {
    const msg = el('p', { class: 'msg' });
    const form = el('form', { class: 'card form', novalidate: true },
      el('h1', {}, 'Crear cuenta de postor'),
      el('label', {}, 'Nombre completo', el('input', { name: 'name', autocomplete: 'name', required: true, maxlength: 80 })),
      el('label', {}, 'Correo', el('input', { name: 'email', type: 'email', autocomplete: 'email', required: true })),
      el('label', {}, 'Contraseña', el('input', { name: 'password', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 })),
      el('p', { class: 'muted small' }, 'Mínimo 10 caracteres con al menos 3 de: minúsculas, mayúsculas, números y símbolos.'),
      el('button', { class: 'btn primary', type: 'submit' }, 'Registrarme'),
      msg,
      el('p', { class: 'muted' }, '¿Ya tienes cuenta? ', el('a', { href: '#/login' }, 'Inicia sesión')),
    );
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = new FormData(form);
      try {
        const r = await api('/auth/register', { method: 'POST', body: Object.fromEntries(f) });
        form.replaceChildren(el('h1', {}, 'Listo'), el('p', {}, r.message), el('a', { class: 'btn primary', href: '#/login' }, 'Ir a iniciar sesión'));
      } catch (err) {
        msg.textContent = err.message;
        msg.className = 'msg error';
      }
    });
    $view.replaceChildren(form);
  }

  // ---------- Vistas: subastas ----------
  async function renderList({ silent = false } = {}) {
    if (!silent) $view.replaceChildren(el('p', { class: 'muted' }, 'Cargando…'));
    const { auctions } = await api('/auctions');
    clearTimers();
    if (auctions[0]) state.clockOffset = auctions[0].server_time - Date.now();
    const banner = state.user.status === 'pending'
      ? el('div', { class: 'card warn' }, 'Tu cuenta está pendiente de aprobación. Podrás ofertar cuando el administrador la apruebe.')
      : null;
    const items = auctions.map((a) => {
      const timer = el('span', { class: 'timer' });
      if (a.status === 'activa') countdown(timer, a.ends_at, 'Cierra en ');
      else if (a.status === 'programada') countdown(timer, a.starts_at, 'Abre en ');
      return el('a', { class: 'card auction-item', href: `#/subasta/${a.id}` },
        el('div', { class: 'row' }, badge(a.status), el('span', { class: 'chip' }, a.mode === 'sellada' ? '🔒 Sellada' : '📈 Abierta')),
        el('h2', {}, a.title),
        el('div', { class: 'row' },
          el('strong', { class: 'price' }, a.mode === 'abierta' || a.status === 'cerrada'
            ? money(a.current_price_cents ?? a.starting_price_cents) : `Base ${money(a.starting_price_cents)}`),
          timer),
        el('div', { class: 'muted small' }, `${a.bid_count} ofertas · ${a.bidder_count} participantes`,
          a.is_leader && a.status === 'activa' ? el('span', { class: 'chip ok' }, 'Vas ganando') : null,
          a.i_won ? el('span', { class: 'chip ok' }, '🏆 Ganaste') : null),
      );
    });
    $view.replaceChildren(banner || '', el('h1', {}, 'Subastas'),
      items.length ? el('div', { class: 'list' }, items) : el('p', { class: 'muted' }, 'Aún no hay subastas publicadas.'));
  }

  async function renderAuction(id, { silent = false } = {}) {
    state.currentAuctionId = id;
    if (!silent) $view.replaceChildren(el('p', { class: 'muted' }, 'Cargando…'));
    let a;
    try {
      ({ auction: a } = await api(`/auctions/${id}`));
    } catch (err) {
      $view.replaceChildren(el('div', { class: 'card' }, err.message, el('p', {}, el('a', { href: '#/' }, 'Volver'))));
      return;
    }
    const keepValue = $view.querySelector('input[name=amount]')?.value;
    clearTimers();
    state.clockOffset = a.server_time - Date.now();
    const isAdmin = state.user.role === 'admin';
    const timer = el('div', { class: 'big-timer' });
    if (a.status === 'activa') countdown(timer, a.ends_at, '⏱ ');
    else if (a.status === 'programada') countdown(timer, a.starts_at, 'Abre en ');
    else if (a.status === 'pausada') timer.textContent = '⏸ Pausada por el administrador';
    else timer.textContent = a.status === 'cerrada' ? `Cerrada el ${fmtDate(a.ends_at)}` : 'Cancelada';

    const summary = el('div', { class: 'card' },
      el('div', { class: 'row' }, badge(a.status), el('span', { class: 'chip' }, a.mode === 'sellada' ? '🔒 Licitación sellada' : '📈 Subasta abierta')),
      el('h1', {}, a.title),
      a.description ? el('p', { class: 'desc' }, a.description) : null,
      timer,
      el('dl', { class: 'facts' },
        el('dt', {}, 'Precio base'), el('dd', {}, money(a.starting_price_cents)),
        a.mode === 'abierta' ? [el('dt', {}, 'Incremento mínimo'), el('dd', {}, money(a.min_increment_cents))] : null,
        a.current_price_cents != null ? [el('dt', {}, a.status === 'cerrada' ? 'Oferta ganadora' : 'Oferta actual'),
          el('dd', { class: 'price' }, money(a.current_price_cents))] : null,
        a.leader ? [el('dt', {}, 'Líder'), el('dd', {}, a.leader + (a.is_leader ? ' (tú)' : ''))] : null,
        el('dt', {}, 'Ofertas'), el('dd', {}, `${a.bid_count} de ${a.bidder_count} participantes`),
        a.my_alias ? [el('dt', {}, 'Tu seudónimo'), el('dd', {}, a.my_alias)] : null,
        a.my_best_bid_cents != null ? [el('dt', {}, 'Tu mejor oferta'), el('dd', {}, money(a.my_best_bid_cents))] : null,
      ),
      a.status === 'cerrada' ? el('div', { class: `result ${a.i_won ? 'ok' : ''}` },
        a.i_won ? '🏆 ¡Ganaste esta subasta! El administrador te contactará.'
          : a.winner ? `Ganador: ${a.winner} con ${money(a.winning_bid_cents)}` : 'Cerró sin ofertas.',
        a.winner_contact ? el('div', { class: 'small' }, `Contacto: ${a.winner_contact.name} · ${a.winner_contact.email}`) : null,
      ) : null,
    );

    let bidForm = null;
    if (!isAdmin && a.status === 'activa') {
      const canBid = state.user.status === 'active' && !(a.mode === 'sellada' && a.my_best_bid_cents != null) && !a.is_leader;
      const msg = el('p', { class: 'msg' });
      const input = el('input', { name: 'amount', inputmode: 'decimal', autocomplete: 'off', required: true,
        placeholder: `Mínimo ${money(a.min_next_bid_cents)}` });
      if (keepValue) input.value = keepValue;
      bidForm = el('form', { class: 'card form bid-form' },
        el('h2', {}, a.mode === 'sellada' ? 'Tu oferta sellada' : 'Ofertar'),
        a.mode === 'sellada' ? el('p', { class: 'muted small' }, 'Nadie (ni el administrador) verá los montos hasta el cierre. Solo puedes enviar una oferta.') : null,
        el('label', {}, 'Monto', input),
        a.mode === 'abierta' ? el('div', { class: 'quick' },
          [1, 2, 5].map((k) => el('button', { type: 'button', class: 'btn ghost', onclick: () => {
            input.value = ((a.min_next_bid_cents + (k - 1) * a.min_increment_cents) / 100).toFixed(2);
          } }, `+${money(k * a.min_increment_cents)}`))) : null,
        el('button', { class: 'btn primary', type: 'submit', disabled: !canBid }, 'Enviar oferta'),
        !canBid ? el('p', { class: 'muted small' }, state.user.status !== 'active' ? 'Tu cuenta aún no está aprobada.'
          : a.is_leader ? 'Vas ganando. Espera a que alguien supere tu oferta.' : 'Ya enviaste tu oferta.') : null,
        msg,
      );
      bidForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const cents = parseMoney(input.value);
        if (!cents) { msg.textContent = 'Monto inválido'; msg.className = 'msg error'; return; }
        if (!confirm(`¿Confirmas tu oferta de ${money(cents)}? No se puede deshacer.`)) return;
        try {
          const r = await api(`/auctions/${a.id}/bids`, { method: 'POST', body: { amount_cents: cents } });
          input.value = '';
          toast(r.extended_to ? 'Oferta registrada. El cierre se extendió 2 minutos.' : 'Oferta registrada', 'ok');
          renderAuction(a.id, { silent: true });
        } catch (err) {
          msg.textContent = err.message + (err.data?.min_next_bid_cents ? ` (mínimo ${money(err.data.min_next_bid_cents)})` : '');
          msg.className = 'msg error';
        }
      });
    }

    const adminBox = isAdmin ? adminAuctionControls(a) : null;
    let bidsBox = null;
    if (a.bids) {
      bidsBox = el('div', { class: 'card' }, el('h2', {}, 'Ofertas'),
        a.bids.length ? el('ol', { class: 'bids' }, a.bids.map((b) => el('li', { class: b.mine ? 'mine' : '' },
          el('span', {}, b.alias + (b.mine ? ' (tú)' : '') + (b.name ? ` · ${b.name}` : '')),
          el('strong', {}, money(b.amount_cents)),
          el('span', { class: 'muted small' }, fmtDate(b.created_at))))) : el('p', { class: 'muted' }, 'Sin ofertas todavía.'));
    } else if (a.sealed_participants) {
      bidsBox = el('div', { class: 'card' }, el('h2', {}, 'Participantes (montos ocultos hasta el cierre)'),
        a.sealed_participants.length ? el('ul', {}, a.sealed_participants.map((n) => el('li', {}, n))) : el('p', { class: 'muted' }, 'Nadie ha ofertado aún.'));
    }
    $view.replaceChildren(el('a', { href: isAdmin ? '#/admin' : '#/', class: 'back' }, '← Volver'), summary, adminBox || '', bidForm || '', bidsBox || '');
  }

  // ---------- Panel del administrador ----------
  function adminAuctionControls(a) {
    const act = (action, label, cls = 'ghost', confirmMsg) => el('button', {
      class: `btn ${cls}`,
      onclick: async () => {
        if (confirmMsg && !confirm(confirmMsg)) return;
        try {
          await api(`/admin/auctions/${a.id}/action`, { method: 'POST', body: { action } });
          toast('Hecho', 'ok');
          if (state.currentAuctionId === a.id) renderAuction(a.id, { silent: true }); else refreshAdmin();
        } catch (err) { toast(err.message, 'error'); }
      },
    }, label);
    const buttons = [];
    if (a.status === 'borrador') buttons.push(act('publish', 'Publicar', 'primary'));
    if (a.status === 'activa' || a.status === 'programada') buttons.push(act('pause', '⏸ Pausar'));
    if (a.status === 'pausada') buttons.push(act('resume', '▶ Reanudar', 'primary'));
    if (['activa', 'programada', 'pausada'].includes(a.status)) buttons.push(act('close', '⏹ Cerrar ya', 'warn', '¿Cerrar ahora y adjudicar al mejor postor?'));
    if (!['cerrada', 'cancelada'].includes(a.status)) buttons.push(act('cancel', 'Cancelar', 'danger', '¿Cancelar esta subasta? Nadie ganará.'));
    return buttons.length ? el('div', { class: 'admin-controls' }, buttons) : null;
  }

  let adminTab = 'resumen';
  async function renderAdmin() {
    state.currentAuctionId = null;
    const tabs = ['resumen', 'subastas', 'usuarios', 'nueva', 'auditoria'];
    const labels = { resumen: 'Resumen', subastas: 'Subastas', usuarios: 'Usuarios', nueva: '+ Nueva', auditoria: 'Auditoría' };
    const tabBar = el('div', { class: 'tabs', role: 'tablist' }, tabs.map((t) => el('button', {
      role: 'tab', class: t === adminTab ? 'active' : '', 'aria-selected': t === adminTab ? 'true' : 'false',
      onclick: () => { adminTab = t; renderAdmin(); },
    }, labels[t])));
    const body = el('div', { id: 'admin-body' }, el('p', { class: 'muted' }, 'Cargando…'));
    $view.replaceChildren(tabBar, body);
    await refreshAdmin();
  }

  let refreshing = null;
  async function refreshAdmin() {
    const body = document.getElementById('admin-body');
    if (!body) return;
    if (refreshing) return refreshing;
    refreshing = (async () => {
      try {
        clearTimers();
        const content = await ({
          resumen: adminSummary, subastas: adminAuctions, usuarios: adminUsers, nueva: adminNew, auditoria: adminAudit,
        })[adminTab]();
        const target = document.getElementById('admin-body');
        if (target && !(adminTab === 'nueva' && target.childElementCount && target.querySelector('form'))) target.replaceChildren(content);
      } catch (err) {
        toast(err.message, 'error');
      } finally {
        refreshing = null;
      }
    })();
    return refreshing;
  }

  async function adminSummary() {
    const d = await api('/admin/dashboard');
    const stat = (n, label, href) => el(href ? 'a' : 'div', { class: 'stat', href }, el('strong', {}, String(n)), el('span', {}, label));
    const notifBtn = 'Notification' in window && Notification.permission !== 'granted'
      ? el('button', { class: 'btn ghost', onclick: async () => {
        const p = await Notification.requestPermission();
        toast(p === 'granted' ? 'Notificaciones activadas' : 'Permiso denegado', p === 'granted' ? 'ok' : 'error');
        refreshAdmin();
      } }, '🔔 Activar notificaciones en este celular') : null;
    const regToggle = el('label', { class: 'switch' },
      el('input', { type: 'checkbox', checked: d.registrations_open, onchange: async (e) => {
        try {
          await api('/admin/settings', { method: 'POST', body: { registrations_open: e.target.checked } });
          toast(e.target.checked ? 'Registro abierto' : 'Registro cerrado', 'ok');
        } catch (err) { toast(err.message, 'error'); e.target.checked = !e.target.checked; }
      } }),
      ' Permitir nuevos registros');
    const panic = el('button', { class: 'btn danger block', onclick: async () => {
      const code = prompt('BOTÓN DE PÁNICO\nPausa todas las subastas, expulsa a todos los postores y cierra el registro.\n\nIngresa tu código 2FA para confirmar:');
      if (!code) return;
      try {
        const r = await api('/admin/panic', { method: 'POST', body: { totp: code.trim() } });
        toast(`Pánico activado: ${r.paused} subastas pausadas`, 'ok');
        refreshAdmin();
      } catch (err) { toast(err.message, 'error'); }
    } }, '🚨 Botón de pánico');
    return el('div', {},
      el('div', { class: 'stats' },
        stat(d.live_auctions, 'Subastas en vivo'),
        stat(d.pending_users, 'Por aprobar'),
        stat(d.active_users, 'Postores activos'),
        stat(d.bids_24h, 'Ofertas 24 h'),
        stat(d.online_sockets, 'Conectados ahora')),
      d.pending_users ? el('button', { class: 'btn primary block', onclick: () => { adminTab = 'usuarios'; renderAdmin(); } },
        `Revisar ${d.pending_users} solicitud(es) pendiente(s)`) : null,
      el('div', { class: 'card form' }, el('h2', {}, 'Control'), regToggle, notifBtn, panic),
    );
  }

  async function adminAuctions() {
    const { auctions } = await api('/auctions');
    if (!auctions.length) return el('p', { class: 'muted' }, 'No hay subastas. Crea una en "+ Nueva".');
    return el('div', { class: 'list' }, auctions.map((a) => {
      const timer = el('span', { class: 'timer' });
      if (a.status === 'activa') countdown(timer, a.ends_at, '');
      return el('div', { class: 'card' },
        el('div', { class: 'row' }, badge(a.status), el('span', { class: 'chip' }, a.mode), timer),
        el('h2', {}, el('a', { href: `#/subasta/${a.id}` }, `#${a.id} ${a.title}`)),
        el('div', { class: 'muted small' },
          `${a.bid_count} ofertas · ${a.mode === 'abierta' || a.status === 'cerrada' ? `actual ${money(a.current_price_cents)}` : 'montos sellados'}`),
        adminAuctionControls(a));
    }));
  }

  async function adminUsers() {
    const { users } = await api('/admin/users');
    const act = (u, action, label, cls = 'ghost', msg) => el('button', { class: `btn small ${cls}`, onclick: async () => {
      if (msg && !confirm(msg)) return;
      try {
        await api(`/admin/users/${u.id}/action`, { method: 'POST', body: { action } });
        toast('Hecho', 'ok');
        refreshAdmin();
      } catch (err) { toast(err.message, 'error'); }
    } }, label);
    return el('div', { class: 'list' }, users.map((u) => el('div', { class: 'card user' },
      el('div', { class: 'row' }, el('strong', {}, u.name), el('span', { class: `badge us-${u.status}` },
        { pending: 'Pendiente', active: 'Activo', blocked: 'Bloqueado' }[u.status]), u.role === 'admin' ? el('span', { class: 'chip' }, 'admin') : null),
      el('div', { class: 'muted small' }, `${u.email} · ${u.bids} ofertas · ${u.sessions} sesiones · desde ${fmtDate(u.created_at)}`),
      u.role !== 'admin' ? el('div', { class: 'admin-controls' },
        u.status === 'pending' ? act(u, 'approve', '✔ Aprobar', 'primary') : null,
        u.status !== 'blocked' ? act(u, 'block', 'Bloquear', 'danger', `¿Bloquear a ${u.name}? Se cerrarán sus sesiones.`) : act(u, 'unblock', 'Desbloquear'),
        u.sessions > 0 ? act(u, 'logout', 'Cerrar sesiones') : null) : null,
    )));
  }

  function adminNew() {
    const msg = el('p', { class: 'msg' });
    const pad = (n) => String(n).padStart(2, '0');
    const localInput = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const now = new Date();
    const form = el('form', { class: 'card form' },
      el('h2', {}, 'Nueva subasta / licitación'),
      el('label', {}, 'Título', el('input', { name: 'title', required: true, maxlength: 120 })),
      el('label', {}, 'Descripción', el('textarea', { name: 'description', rows: 3, maxlength: 2000 })),
      el('label', {}, 'Modalidad', el('select', { name: 'mode' },
        el('option', { value: 'abierta' }, 'Abierta (ofertas visibles, gana la más alta)'),
        el('option', { value: 'sellada' }, 'Sellada (montos ocultos hasta el cierre, 1 oferta por persona)'))),
      el('label', {}, 'Precio base', el('input', { name: 'starting', inputmode: 'decimal', required: true, placeholder: '1000.00' })),
      el('label', {}, 'Incremento mínimo (abierta)', el('input', { name: 'increment', inputmode: 'decimal', value: '10.00' })),
      el('label', {}, 'Inicio', el('input', { name: 'starts', type: 'datetime-local', value: localInput(now) })),
      el('label', {}, 'Cierre', el('input', { name: 'ends', type: 'datetime-local', required: true,
        value: localInput(new Date(now.getTime() + 24 * 3600 * 1000)) })),
      el('label', { class: 'switch' }, el('input', { type: 'checkbox', name: 'publish', checked: true }), ' Publicar inmediatamente'),
      el('button', { class: 'btn primary', type: 'submit' }, 'Crear'),
      msg,
    );
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = new FormData(form);
      const starting = parseMoney(f.get('starting'));
      const increment = parseMoney(f.get('increment') || '1');
      if (!starting || !increment) { msg.textContent = 'Revisa los montos'; msg.className = 'msg error'; return; }
      const startsMs = new Date(f.get('starts')).getTime();
      try {
        const r = await api('/admin/auctions', { method: 'POST', body: {
          title: f.get('title'), description: f.get('description'), mode: f.get('mode'),
          starting_price_cents: starting, min_increment_cents: increment,
          starts_at: startsMs <= Date.now() ? null : startsMs,
          ends_at: new Date(f.get('ends')).getTime(), publish: f.get('publish') === 'on',
        } });
        toast('Subasta creada', 'ok');
        location.hash = `#/subasta/${r.id}`;
      } catch (err) {
        msg.textContent = err.message;
        msg.className = 'msg error';
      }
    });
    return form;
  }

  async function adminAudit() {
    const [{ entries }, v] = await Promise.all([api('/admin/audit?limit=150'), api('/admin/audit/verify')]);
    return el('div', {},
      el('div', { class: `card ${v.ok ? 'ok' : 'warn'}` }, v.ok
        ? `✔ Bitácora íntegra: ${v.checked} registros encadenados verificados.`
        : `✖ ¡ALERTA! La bitácora fue alterada en el registro #${v.brokenAt}.`),
      el('ol', { class: 'audit' }, entries.map((e) => el('li', {},
        el('div', { class: 'row' }, el('strong', {}, e.action), el('span', { class: 'muted small' }, fmtDate(e.ts))),
        el('div', { class: 'muted small' }, `${e.actor || 'sistema'} · ${JSON.stringify(e.details)}`)))));
  }

  // ---------- Enrutador ----------
  async function route() {
    clearTimers();
    state.currentAuctionId = null;
    const hash = location.hash || '#/';
    if (!state.user) {
      renderNav();
      return hash === '#/registro' ? renderRegister() : renderLogin();
    }
    renderNav();
    connectSocket();
    const m = hash.match(/^#\/subasta\/(\d+)$/);
    try {
      if (m) return await renderAuction(Number(m[1]));
      if (hash.startsWith('#/admin') && state.user.role === 'admin') return await renderAdmin();
      if (hash === '#/login' || hash === '#/registro') { location.hash = '#/'; return; }
      return await renderList();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  window.addEventListener('hashchange', route);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && state.user) route(); });

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

  loadMe().catch(() => null).finally(route);
})();
