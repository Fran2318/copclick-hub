import http from 'http'
import crypto from 'crypto'
import { CONFIG } from './config.js'
import { eco } from './supabase.js'
import { attachHub, connectedCounts, blockClient, unblockClient } from './hub.js'
import { startIngest, reloadIngest } from './ingest.js'

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
      'access-control-allow-headers': 'content-type, x-admin-key',
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

  json(res, 200, { service: 'COPCLICK Hub' })
})

attachHub(server)
server.listen(CONFIG.port, () => {
  console.log(`[hub] escuchando en :${CONFIG.port}  (WS en /ws/print)`)
})
startIngest()
