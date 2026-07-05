// Eventos en vivo hacia COPCLICK Core (lado tienda) vía Server-Sent Events.
// clientId -> Set<res> de conexiones SSE abiertas.
const listeners = new Map()

export function addStoreListener(clientId, res) {
  if (!listeners.has(clientId)) listeners.set(clientId, new Set())
  listeners.get(clientId).add(res)
}

export function removeStoreListener(clientId, res) {
  listeners.get(clientId)?.delete(res)
}

export function notifyStore(clientId, data) {
  const set = listeners.get(clientId)
  if (!set) return
  const msg = `data: ${JSON.stringify(data)}\n\n`
  for (const res of set) {
    try {
      res.write(msg)
    } catch {
      set.delete(res)
    }
  }
}

// Heartbeat para que los proxies (Railway) no corten las conexiones inactivas.
setInterval(() => {
  for (const set of listeners.values())
    for (const res of set) {
      try {
        res.write(':hb\n\n')
      } catch {
        set.delete(res)
      }
    }
}, 25000)
