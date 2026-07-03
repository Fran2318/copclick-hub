import http from 'http'
import { CONFIG } from './config.js'
import { eco } from './supabase.js'
import { attachHub, connectedCounts, blockClient, unblockClient } from './hub.js'
import { startIngest } from './ingest.js'

function json(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(JSON.stringify(obj))
}
const isAdmin = (req) => CONFIG.adminKey && req.headers['x-admin-key'] === CONFIG.adminKey

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if (url.pathname === '/health') {
    return json(res, 200, { ok: true, connected: connectedCounts() })
  }

  if (url.pathname.startsWith('/admin/')) {
    if (!isAdmin(req)) return json(res, 401, { error: 'unauthorized' })

    if (url.pathname === '/admin/clients' && req.method === 'GET') {
      const { data } = await eco.from('print_clients').select('id,name,status,store_name,last_seen_at')
      const conn = connectedCounts()
      return json(res, 200, (data ?? []).map((c) => ({ ...c, connected: (conn[c.id] ?? 0) > 0 })))
    }
    const m = url.pathname.match(/^\/admin\/clients\/([0-9a-f-]+)\/(block|unblock)$/)
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
