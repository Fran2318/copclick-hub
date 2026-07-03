import { WebSocketServer } from 'ws'
import crypto from 'crypto'
import { eco } from './supabase.js'

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex')

// tenantId (print_clients.id) -> Set<WebSocket> de SUS agentes conectados
const agentsByTenant = new Map()

export function connectedCounts() {
  const out = {}
  for (const [tid, set] of agentsByTenant) out[tid] = [...set].filter((w) => w.readyState === 1).length
  return out
}

/** Emite un pedido SOLO a los agentes del cliente; si no hay ninguno, lo encola. */
export async function emitNewOrder(tenantId, payload) {
  const set = agentsByTenant.get(tenantId)
  const online = set && [...set].some((w) => w.readyState === 1)
  const order_ref = payload?.order_number ?? null

  if (online) {
    await eco.from('print_jobs').insert({ client_id: tenantId, order_ref, payload, status: 'sent' })
    const msg = JSON.stringify({ type: 'new_order', data: payload })
    for (const w of set) if (w.readyState === 1) w.send(msg)
    return 'sent'
  }
  await eco.from('print_jobs').insert({ client_id: tenantId, order_ref, payload, status: 'pending' })
  return 'queued'
}

async function flushQueue(tenantId) {
  const set = agentsByTenant.get(tenantId)
  if (!set || set.size === 0) return
  const { data: jobs } = await eco
    .from('print_jobs')
    .select('id,payload')
    .eq('client_id', tenantId)
    .eq('status', 'pending')
    .order('created_at')
  for (const job of jobs ?? []) {
    const msg = JSON.stringify({ type: 'new_order', data: job.payload })
    for (const w of set) if (w.readyState === 1) w.send(msg)
    await eco.from('print_jobs').update({ status: 'sent' }).eq('id', job.id)
  }
}

export async function blockClient(tenantId) {
  await eco.from('print_clients').update({ status: 'blocked' }).eq('id', tenantId)
  for (const w of agentsByTenant.get(tenantId) ?? []) {
    try {
      w.close(4003, 'blocked')
    } catch {
      /* noop */
    }
  }
}
export async function unblockClient(tenantId) {
  await eco.from('print_clients').update({ status: 'active' }).eq('id', tenantId)
}

export function attachHub(httpServer) {
  const wss = new WebSocketServer({ server: httpServer, path: '/ws/print' })

  wss.on('connection', async (socket, req) => {
    try {
      const url = new URL(req.url ?? '', 'http://localhost')
      const token = url.searchParams.get('token') ?? ''

      // Auth server-side: buscar cliente por hash del token
      const { data: client } = await eco
        .from('print_clients')
        .select('id,status,name')
        .eq('token_hash', sha256(token))
        .maybeSingle()

      if (!client) {
        socket.close(4001, 'unauthorized')
        return
      }
      if (client.status === 'blocked') {
        socket.close(4003, 'blocked')
        return
      }

      const tid = client.id
      if (!agentsByTenant.has(tid)) agentsByTenant.set(tid, new Set())
      agentsByTenant.get(tid).add(socket)
      socket.send(JSON.stringify({ type: 'connected', message: `COPCLICK Print · ${client.name}` }))
      eco.from('print_clients').update({ last_seen_at: new Date().toISOString() }).eq('id', tid).then(() => {})

      await flushQueue(tid)

      socket.isAlive = true
      socket.on('pong', () => {
        socket.isAlive = true
      })

      socket.on('message', async (raw) => {
        let msg
        try {
          msg = JSON.parse(raw.toString())
        } catch {
          return
        }
        if (msg.type === 'print_ok') {
          let u = eco
            .from('print_jobs')
            .update({ status: 'printed', printed_at: new Date().toISOString() })
            .eq('client_id', tid)
            .eq('status', 'sent')
          if (msg.order_number) u = u.eq('order_ref', msg.order_number)
          await u
          console.log(`[hub] ${client.name}: ticket impreso ${msg.order_number ?? ''}`)
        }
        if (msg.type === 'print_error') {
          await eco
            .from('print_jobs')
            .update({ status: 'error', error: msg.error ?? '' })
            .eq('client_id', tid)
            .eq('status', 'sent')
          console.warn(`[hub] ${client.name}: error impresión ${msg.error ?? ''}`)
        }
      })

      socket.on('close', () => agentsByTenant.get(tid)?.delete(socket))
      socket.on('error', () => agentsByTenant.get(tid)?.delete(socket))
    } catch (e) {
      try {
        socket.close(1011, 'server error')
      } catch {
        /* noop */
      }
      console.error('[hub] error en conexión:', e.message)
    }
  })

  // Heartbeat: descarta agentes muertos cada 30s (todos los tenants)
  setInterval(() => {
    for (const set of agentsByTenant.values())
      for (const w of set) {
        if (w.isAlive === false) {
          try {
            w.terminate()
          } catch {
            /* noop */
          }
          set.delete(w)
          continue
        }
        w.isAlive = false
        try {
          w.ping()
        } catch {
          /* noop */
        }
      }
  }, 30000)

  return wss
}
