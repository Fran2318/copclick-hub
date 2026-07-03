# COPCLICK Hub

Servidor **WebSocket multi-tenant** de impresión del ecosistema COPCLICK.
- Los agentes `.exe` (uno por local) se conectan a `wss://<hub>/ws/print?token=…`.
- El Hub **escucha el Realtime** del Supabase de cada tienda (INSERT en `orders`) y
  **empuja** el pedido al `.exe` del cliente correspondiente. Si el agente está offline, lo
  **encola** (`print_jobs`) y lo manda al reconectar.
- **Bloqueo server-side** por cliente (para cortar el servicio si no paga).

> Arquitectura confirmada: **Opción A (hub central)** · **ingesta por Realtime** · hosting en **Railway**.
> El `.exe` actual de los clientes **no cambia**; solo su `config.json → serverUrl` apunta al Hub.

## Estructura
```
src/
├── index.js        # HTTP (/health, /admin/*) + arranque del WS + ingesta
├── hub.js          # WS multi-tenant: auth por token, cola, bloqueo, heartbeat
├── ingest.js       # Realtime de cada tienda → emitNewOrder
├── payload.js      # mapea orders/order_items → payload del ticket
├── supabase.js     # clientes Supabase (ecosistema + por tienda)
├── config.js       # variables de entorno
└── create-client.js# alta de clientes (genera token, guarda hash)
supabase/hub-schema.sql  # tablas print_clients / print_jobs (Supabase del ecosistema)
```

## Prerequisitos (una vez)
1. **Tablas del Hub**: en el Supabase del **ecosistema** (`xpglkncnekmcpxpeaznk`) → SQL Editor, correr `supabase/hub-schema.sql`.
2. **Realtime en Paradise**: en el Supabase de **Paradise** → SQL Editor:
   ```sql
   do $$ begin
     if not exists (select 1 from pg_publication_tables
        where pubname='supabase_realtime' and schemaname='public' and tablename='orders') then
       alter publication supabase_realtime add table public.orders;
     end if;
   end $$;
   ```

## Deploy en Railway (por GitHub)
1. Subí esta carpeta `copclick-hub` a un repo de GitHub nuevo.
2. En Railway → **New Project → Deploy from GitHub repo** → elegí ese repo.
3. En **Variables** del servicio cargá:
   - `ECOSYSTEM_SUPABASE_URL` = `https://xpglkncnekmcpxpeaznk.supabase.co`
   - `ECOSYSTEM_SERVICE_KEY` = *(service_role del ecosistema — Settings → API)*
   - `ADMIN_KEY` = *(una clave larga aleatoria)*
   - (`PORT` la pone Railway sola.)
4. Railway detecta Node y corre `npm start`. Cuando termine, en **Settings → Networking → Generate Domain** obtenés la URL pública (`https://<algo>.up.railway.app`). El WS es `wss://<algo>.up.railway.app`.
5. Probá que vive: abrí `https://<algo>.up.railway.app/health` → debe responder `{"ok":true,...}`.

## Alta del cliente Paradise
Localmente (necesitás las mismas variables en un `.env`, ver `.env.example`):
```bash
npm install
npm run create-client
```
Te pide: nombre, `store_web`, la **URL del Supabase de Paradise** y su **service_role** (queda guardada server-side). Devuelve el **TOKEN** una sola vez.

## Conectar el `.exe` de Paradise
En su `config.json`:
```jsonc
{
  "serverUrl": "wss://<algo>.up.railway.app",   // sin /ws/print
  "token": "EL-TOKEN-QUE-DEVOLVIO-create-client",
  "printerName": "EPSON TM-T88V Receipt",
  "retryAttempts": 0
}
```
Reiniciá el `.exe`: debería loguear `✅ Conectado`. Hacé una compra de prueba en paradisemoda.com → imprime.

## Admin (opcional)
```bash
curl -H "x-admin-key: <ADMIN_KEY>" https://<hub>/admin/clients          # lista + conectado
curl -X POST -H "x-admin-key: <ADMIN_KEY>" https://<hub>/admin/clients/<id>/block
curl -X POST -H "x-admin-key: <ADMIN_KEY>" https://<hub>/admin/clients/<id>/unblock
```
(El panel visual vive en COPCLICK Core; estos endpoints son la API que va a consumir.)
