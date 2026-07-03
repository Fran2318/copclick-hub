import http from 'http'
import crypto from 'crypto'
import { CONFIG } from './config.js'
import { eco } from './supabase.js'
import { attachHub, connectedCounts, blockClient, unblockClient } from './hub.js'
import { startIngest, reloadIngest } from './ingest.js'
import {
  activate,
  setupAdmin,
  login,
  listUsers,
  createUser,
  storeOrders,
  storeProducts,
  storeDashboard,
  getOrder,
  setOrderStatus,
  deleteOrder,
  reprintOrder,
  verifySession
} from './store.js'

function json(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' })
  res.end(JSON.stringify(obj))
}
const isAdmin = (req) => CONFIG.adminKey && req.headers['x-admin-key'] === CONFIG.adminKey

function readBody(req) {
  return new Promise((resolve) => {
    let raw = ''
    req.on('data', (c) => (raw += c))
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch {
        resolve({})
      }
    })
  })
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost')

  // CORS preflight (para llamar desde COPCLICK Core)
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type, x-admin-key, authorization',
      'access-control-allow-methods': 'GET, POST, OPTIONS'
    })
    return res.end()
  }

  if (url.pathname === '/health') {
    return json(res, 200, { ok: true, connected: connectedCounts() })
  }

  if (url.pathname.startsWith('/admin/')) {
    if (!isAdmin(req)) return json(res, 401, { error: 'unauthorized' })

    // Lista de clientes + si están conectados
    if (url.pathname === '/admin/clients' && req.method === 'GET') {
      const { data } = await eco
        .from('print_clients')
        .select('id,name,status,store_name,store_web,last_seen_at,created_at')
      const conn = connectedCounts()
      return json(res, 200, (data ?? []).map((c) => ({ ...c, connected: (conn[c.id] ?? 0) > 0 })))
    }

    // Alta de cliente (genera token, guarda hash + credenciales de la tienda)
    if (url.pathname === '/admin/clients' && req.method === 'POST') {
      const b = await readBody(req)
      if (!b.name || !b.store_supabase_url || !b.store_service_key) {
        return json(res, 400, { error: 'faltan name / store_supabase_url / store_service_key' })
      }
      const token = crypto.randomBytes(24).toString('hex')
      const token_hash = crypto.createHash('sha256').update(token).digest('hex')
      const { data, error } = await eco
        .from('print_clients')
        .insert({
          name: b.name,
          token_hash,
          store_name: b.store_name || b.name,
          store_web: b.store_web || '',
          store_supabase_url: b.store_supabase_url,
          store_service_key: b.store_service_key,
          status: 'active'
        })
        .select('id')
        .single()
      if (error) return json(res, 400, { error: error.message })
      await reloadIngest() // empieza a escuchar la tienda nueva ya
      return json(res, 200, { id: data.id, token })
    }

    // Recarga en caliente de la ingesta (nuevos clientes sin redeploy)
    if (url.pathname === '/admin/reload' && req.method === 'POST') {
      const n = await reloadIngest()
      return json(res, 200, { ok: true, listening: n })
    }

    // Historial de impresiones de un cliente
    let m = url.pathname.match(/^\/admin\/clients\/([0-9a-f-]+)\/jobs$/)
    if (m && req.method === 'GET') {
      const { data } = await eco
        .from('print_jobs')
        .select('id,order_ref,status,created_at,printed_at,error')
        .eq('client_id', m[1])
        .order('created_at', { ascending: false })
        .limit(30)
      return json(res, 200, data ?? [])
    }

    // Bloquear / desbloquear
    m = url.pathname.match(/^\/admin\/clients\/([0-9a-f-]+)\/(block|unblock)$/)
    if (m && req.method === 'POST') {
      const [, id, action] = m
      if (action === 'block') await blockClient(id)
      else await unblockClient(id)
      return json(res, 200, { ok: true })
    }

    return json(res, 404, { error: 'not found' })
  }

  // ---------- Lado CLIENTE (tienda): login por código + usuarios + datos ----------
  if (url.pathname.startsWith('/store/')) {
    const body = req.method === 'POST' ? await readBody(req) : {}

    // Públicas (sin sesión)
    if (url.pathname === '/store/activate' && req.method === 'POST') {
      return json(res, 200, await activate(body.code))
    }
    if (url.pathname === '/store/setup-admin' && req.method === 'POST') {
      const r = await setupAdmin(body.code, body.name, body.password)
      return json(res, r.error ? 400 : 200, r)
    }
    if (url.pathname === '/store/login' && req.method === 'POST') {
      const r = await login(body.code, body.name, body.password)
      return json(res, r.error ? 401 : 200, r)
    }

    // Con sesión (Bearer token)
    const session = verifySession((req.headers['authorization'] || '').replace(/^Bearer /, ''))
    if (!session) return json(res, 401, { error: 'no autorizado' })

    if (url.pathname === '/store/users' && req.method === 'GET') return json(res, 200, await listUsers(session))
    if (url.pathname === '/store/users' && req.method === 'POST') {
      const r = await createUser(session, body.name, body.password, body.role)
      return json(res, r.error ? 400 : 200, r)
    }
    if (url.pathname === '/store/dashboard') return json(res, 200, await storeDashboard(session))
    if (url.pathname === '/store/orders') return json(res, 200, await storeOrders(session))
    if (url.pathname === '/store/products') return json(res, 200, await storeProducts(session))

    let sm = url.pathname.match(/^\/store\/orders\/([^/]+)$/)
    if (sm && req.method === 'GET') return json(res, 200, await getOrder(session, sm[1]))
    sm = url.pathname.match(/^\/store\/orders\/([^/]+)\/status$/)
    if (sm && req.method === 'POST') return json(res, 200, await setOrderStatus(session, sm[1], body.status))
    sm = url.pathname.match(/^\/store\/orders\/([^/]+)\/delete$/)
    if (sm && req.method === 'POST') return json(res, 200, await deleteOrder(session, sm[1]))
    sm = url.pathname.match(/^\/store\/orders\/([^/]+)\/reprint$/)
    if (sm && req.method === 'POST') return json(res, 200, await reprintOrder(session, sm[1]))

    return json(res, 404, { error: 'not found' })
  }

  json(res, 200, { service: 'COPCLICK Hub' })
})

attachHub(server)
server.listen(CONFIG.port, () => {
  console.log(`[hub] escuchando en :${CONFIG.port}  (WS en /ws/print)`)
})
startIngest()
