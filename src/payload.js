// Mapea un pedido de la tienda (esquema de Paradise) → payload agnóstico new_order
// que ya entiende el .exe y el printer.js (sección 1 del handoff).
export function buildOrderPayload(order, items, client) {
  return {
    store_name: client.store_name || client.name,
    store_web: client.store_web || '',
    order_number: order.order_number,
    customer_name: order.customer_name,
    customer_phone: order.customer_phone,
    customer_address: order.customer_address,
    customer_city: order.customer_city,
    total: Number(order.total || 0),
    shipping_cost: Number(order.shipping_cost || 0),
    shipping_method_name: order.shipping_method_name || '',
    payment_method: order.payment_method || '',
    created_at: order.created_at,
    items: (items || []).map((it) => ({
      product_name: it.product_name,
      quantity: it.quantity,
      unit_price: Number(it.unit_price || 0),
      size: it.size ?? null,
      color: it.color ?? null
    }))
  }
}
