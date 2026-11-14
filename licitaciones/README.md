# LicitApp — licitaciones y subastas seguras, controladas desde tu celular

Aplicación web en tiempo real para organizar **subastas abiertas** y **licitaciones selladas**.
Todos los dispositivos quedan **enlazados en vivo**: cuando alguien oferta, el resto lo ve al instante
y tú (administrador) recibes el aviso en tu celular. Se instala en el celular como una app (PWA).

## Qué puedes hacer desde tu celular (administrador)

- Ver un **resumen en vivo**: subastas activas, solicitudes pendientes, ofertas, personas conectadas.
- **Aprobar, bloquear o expulsar** postores (al bloquear se cierran sus sesiones al instante).
- **Crear** subastas/licitaciones, **pausar, reanudar, cerrar o cancelar** cualquiera.
- Recibir **avisos en tiempo real** (vibración + notificación) de registros, ofertas, cierres e
  inicios de sesión de administrador.
- **Abrir/cerrar el registro** de nuevos postores.
- **Botón de pánico** (pide tu código 2FA): pausa todas las subastas, expulsa a todos los postores y
  cierra el registro.
- Revisar la **bitácora de auditoría** y verificar que nadie la haya alterado.

## Modalidades

| | Abierta | Sellada |
|---|---|---|
| Montos visibles durante la subasta | Sí (con seudónimos) | **No, ni para el administrador** |
| Ofertas por persona | Varias, cada una ≥ actual + incremento | **Una sola** |
| Gana | La más alta (empate: la primera) | La más alta al cierre |
| Anti-“último segundo” | Si alguien oferta en los últimos 2 min, el cierre se extiende 2 min | — |

## Seguridad incluida

- **Contraseñas** con scrypt (parámetros OWASP) y política de contraseña robusta.
- **Doble verificación (2FA/TOTP) obligatoria para el administrador** (Google Authenticator,
  Microsoft Authenticator, Authy…), con protección contra reutilización de códigos.
- **Sesiones** con token aleatorio guardado solo como hash, cookie `HttpOnly` + `Secure` +
  `SameSite=Strict` (`__Host-`), expiración por inactividad (2 h) y absoluta (12 h).
- **Bloqueo temporal** tras 5 intentos fallidos y **límite de peticiones** por IP/usuario.
- **Protección CSRF** (SameSite estricto + verificación de origen + cabecera obligatoria).
- **Cabeceras de seguridad** (CSP estricta sin scripts en línea, HSTS, anti-clickjacking, etc.).
- **Validación en el servidor** de cada oferta dentro de una transacción (sin condiciones de carrera);
  montos en centavos enteros (sin errores de redondeo).
- **Privacidad**: los postores solo ven seudónimos (`Postor-XXXXX`), nunca nombres ni correos.
- **Bitácora encadenada con hashes**: cada acción queda registrada y cualquier modificación se
  detecta. En licitaciones selladas la bitácora guarda un *compromiso* (hash) del monto, no el monto.
- El canal en tiempo real solo **notifica**; todas las acciones pasan por la API validada.
- Sin `innerHTML` con datos de usuarios (previene XSS). Dependencias mínimas, 0 vulnerabilidades.

## Probar en tu computadora

Requiere Node.js 22.13 o superior.

```bash
cd licitaciones
npm install
npm run crear-admin          # crea tu usuario y muestra un QR para tu app de autenticación
                             # (o define SETUP_TOKEN y créalo desde el navegador)
COOKIE_SECURE=false npm start
```

Abre <http://localhost:3000>. Para probar desde el celular en la misma red Wi-Fi usa
`http://IP-DE-TU-PC:3000` (solo para pruebas: en producción **siempre HTTPS**).

Pruebas automáticas: `npm test`

## Tenerla en tu celular (paso a paso con Render)

1. Crea una cuenta en <https://render.com> (puedes entrar con tu GitHub).
2. En Render: **New → Blueprint** → elige el repositorio `juego-secreto` y la rama donde está la app.
   Render lee el archivo `render.yaml` y lo configura todo solo (servidor, HTTPS y disco).
3. Cuando termine, entra al servicio **licitapp → Environment** y copia el valor de `SETUP_TOKEN`.
4. En tu celular abre la dirección `https://licitapp-xxxx.onrender.com` que te da Render.
5. Verás **Configuración inicial**: pega el `SETUP_TOKEN`, pon tu nombre, correo y contraseña,
   toca **“Abrir en mi app de autenticación”** y escribe el código de 6 dígitos.
6. En el menú del navegador toca **“Agregar a pantalla de inicio”**. Ya tienes el ícono de LicitApp.
7. En el Panel toca **“Activar notificaciones en este celular”**.
8. Comparte la dirección con tus postores para que se registren; tú los apruebas desde el Panel.

## Publicarlo en otro proveedor

La app necesita un servidor que se mantenga encendido (por el tiempo real) y un **disco persistente**
para la base de datos. Funciona en Render, Railway, Fly.io o cualquier VPS. (No sirve un hosting
“serverless” tipo Vercel/Netlify, porque no mantiene conexiones en vivo ni guarda el archivo de base de datos.)

**Con Docker en un VPS** (con Caddy delante para HTTPS automático):

```bash
docker build -t licitapp .
docker run -d --name licitapp -p 127.0.0.1:3000:3000 -v licitapp-data:/app/data \
  -e TRUST_PROXY=1 -e FORCE_HTTPS=true -e APP_SECRET=<secreto-largo> licitapp
docker exec -it licitapp npm run crear-admin
```

`Caddyfile`:
```
tu-dominio.com {
    reverse_proxy 127.0.0.1:3000
}
```

**En Render/Railway/Fly**: crea un servicio desde este repositorio con la carpeta `licitaciones`
como raíz, monta un disco en `/app/data` (o define `DB_PATH` en el disco), configura las variables de
`.env.example` y ejecuta `npm run crear-admin` desde la consola del servicio.

### Instalarla en el celular
Abre tu dominio en el celular → menú del navegador → **“Agregar a pantalla de inicio”**.
En el Panel toca **“Activar notificaciones en este celular”**.

## Recomendaciones de operación

- Haz **copias de seguridad** del archivo de base de datos (`data/licitapp.db`) a diario.
- Si pierdes el celular con el 2FA, ejecuta de nuevo `npm run crear-admin` en el servidor con tu
  correo: reinicia contraseña y 2FA y cierra todas tus sesiones.
- Revisa la pestaña **Auditoría** periódicamente: debe decir “Bitácora íntegra”.
- Si la vas a usar para **licitaciones públicas o con dinero real**, revisa la normativa de tu país
  (firma electrónica, custodia de ofertas, términos y condiciones, protección de datos) y considera
  una auditoría de seguridad externa antes de lanzarla.

## Estructura

```
licitaciones/
├── server.js            # arranque
├── src/app.js           # API, reglas de negocio, tiempo real
├── src/security.js      # contraseñas, 2FA, límites de peticiones
├── src/audit.js         # bitácora encadenada
├── src/db.js            # esquema SQLite
├── scripts/crear-admin.js
├── public/              # app web/PWA para celular
└── test/                # pruebas automáticas
```
