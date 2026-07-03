import { eco, storeClient } from './supabase.js'
import { emitNewOrder } from './hub.js'
import { buildOrderPayload } from './payload.js'

const channels = []

// Los ítems se insertan justo después del pedido: reintentamos unos segundos.
async function fetchItems(store, orderId) {
  for (let i = 0; i < 6; i++) {
    const { data } = await store
      .from('order_items')
      .select('product_name,quantity,unit_price,size,color')
      .eq('order_id', orderId)
    if (data && data.length) return data
    await new Promise((r) => setTimeout(r, 500))
  }
  return []
}

export async function startIngest() {
  const { data: clients, error } = await eco
    .from('print_clients')
    .select('id,name,store_name,store_web,store_supabase_url,store_service_key,status')
    .eq('status', 'active')

  if (error) {
    console.error('[ingest] no pude leer print_clients:', error.message)
    return
  }

  for (const c of clients ?? []) {
    if (!c.store_supabase_url || !c.store_service_key) {
      console.warn(`[ingest] ${c.name}: sin credenciales de tienda, salteo`)
      continue
    }
    const store = storeClient(c.store_supabase_url, c.store_service_key)
    const ch = store
      .channel(`orders-${c.id}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'orders' }, async (payload) => {
        try {
          const order = payload.new
          console.log(`[ingest] ${c.name}: pedido nuevo ${order.order_number}`)
          const items = await fetchItems(store, order.id)
          const data = buildOrderPayload(order, items, c)
          const res = await emitNewOrder(c.id, data)
          console.log(`[ingest] ${c.name}: ${order.order_number} → ${res}`)
        } catch (e) {
          console.error('[ingest] error procesando pedido:', e.message)
        }
      })
      .subscribe((status) => console.log(`[ingest] ${c.name}: realtime ${status}`))
    channels.push(ch)
  }
  console.log(`[ingest] escuchando ${channels.length} tienda(s) activa(s)`)
}
