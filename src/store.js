import crypto from 'crypto'
import { eco, storeClient } from './supabase.js'
import { CONFIG } from './config.js'
import { emitNewOrder } from './hub.js'
import { buildOrderPayload } from './payload.js'

const SECRET = CONFIG.sessionSecret

// ---------- Passwords (scrypt, sin dependencias) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.scryptSync(pw, salt, 32).toString('hex')
  return salt + ':' + hash
}
function verifyPassword(pw, stored) {
  try {
    const [salt, hash] = stored.split(':')
    const h = crypto.scryptSync(pw, salt, 32).toString('hex')
    return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash))
  } catch {
    return false
  }
}

// ---------- Sesiones firmadas (HMAC, sin tabla) ----------
export function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url')
  return body + '.' + sig
}
export function verifySession(token) {
  if (!token) return null
  const [body, sig] = token.split('.')
  if (!body || !sig) return null
  const exp = crypto.createHmac('sha256', SECRET).update(body).digest('base64url')
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString())
  } catch {
    return null
  }
}

async function clientByCode(code) {
  const { data } = await eco
    .from('print_clients')
    .select('id,name,store_name,store_web,status')
    .eq('access_code', code)
    .maybeSingle()
  return data
}

// ---------- Auth de tienda ----------
export async function activate(code) {
  const c = await clientByCode(code)
  if (!c) return { error: 'Código de acceso inválido' }
  if (c.status === 'blocked') return { error: 'Esta tienda está bloqueada' }
  const { count } = await eco
    .from('store_users')
    .select('id', { count: 'exact', head: true })
    .eq('client_id', c.id)
  return { store: { name: c.store_name || c.name, web: c.store_web }, hasUsers: (count ?? 0) > 0 }
}

export async function setupAdmin(code, name, password) {
  const c = await clientByCode(code)
  if (!c) return { error: 'Código de acceso inválido' }
  const { count } = await eco
    .from('store_users')
    .select('id', { count: 'exact', head: true })
    .eq('client_id', c.id)
  if ((count ?? 0) > 0) return { error: 'Esta tienda ya tiene usuarios' }
  const { data, error } = await eco
    .from('store_users')
    .insert({ client_id: c.id, name, password_hash: hashPassword(password), role: 'admin' })
    .select('id,name,role')
    .single()
  if (error) return { error: error.message }
  return { token: signSession({ client_id: c.id, user_id: data.id, name: data.name, role: 'admin' }), user: data }
}

export async function login(code, name, password) {
  const c = await clientByCode(code)
  if (!c) return { error: 'Código de acceso inválido' }
  if (c.status === 'blocked') return { error: 'Esta tienda está bloqueada' }
  const { data: u } = await eco
    .from('store_users')
    .select('id,name,role,password_hash')
    .eq('client_id', c.id)
    .eq('name', name)
    .maybeSingle()
  if (!u || !verifyPassword(password, u.password_hash)) return { error: 'Usuario o contraseña incorrectos' }
  return {
    token: signSession({ client_id: c.id, user_id: u.id, name: u.name, role: u.role }),
    user: { id: u.id, name: u.name, role: u.role }
  }
}

export async function listUsers(session) {
  const { data } = await eco
    .from('store_users')
    .select('id,name,role,created_at')
    .eq('client_id', session.client_id)
    .order('created_at')
  return data ?? []
}

export async function createUser(session, name, password, role) {
  if (session.role !== 'admin') return { error: 'Solo el admin puede crear usuarios' }
  if (!name || !password) return { error: 'Faltan nombre o contraseña' }
  const { data, error } = await eco
    .from('store_users')
    .insert({ client_id: session.client_id, name, password_hash: hashPassword(password), role: role === 'admin' ? 'admin' : 'user' })
    .select('id,name,role')
    .single()
  if (error) return { error: error.message.includes('duplicate') ? 'Ya existe un usuario con ese nombre' : error.message }
  return { user: data }
}

// ---------- Datos de la tienda (proxy al Supabase de la tienda) ----------
async function storeDbFor(clientId) {
  const { data: c } = await eco
    .from('print_clients')
    .select('store_supabase_url,store_service_key')
    .eq('id', clientId)
    .single()
  if (!c?.store_supabase_url || !c?.store_service_key) return null
  return storeClient(c.store_supabase_url, c.store_service_key)
}

export async function storeOrders(session) {
  const db = await storeDbFor(session.client_id)
  if (!db) return []
  const { data } = await db
    .from('orders')
    .select('id,order_number,customer_name,customer_phone,total,status,payment_status,payment_method,created_at')
    .order('created_at', { ascending: false })
    .limit(200)
  return (data ?? []).map((o) => ({
    id: o.id,
    numero: o.order_number,
    cliente: o.customer_name,
    telefono: o.customer_phone,
    total: Number(o.total || 0),
    estado: o.status,
    payment_status: o.payment_status,
    metodo_pago: o.payment_method,
    creado_en: o.created_at
  }))
}

export async function getOrder(session, orderId) {
  const db = await storeDbFor(session.client_id)
  if (!db) return null
  const { data: o } = await db.from('orders').select('*').eq('id', orderId).single()
  if (!o) return null
  const { data: items } = await db
    .from('order_items')
    .select('product_name,quantity,unit_price,subtotal,size,color')
    .eq('order_id', orderId)
  return {
    id: o.id,
    numero: o.order_number,
    cliente: o.customer_name,
    telefono: o.customer_phone,
    direccion: o.customer_address,
    ciudad: o.customer_city,
    total: Number(o.total || 0),
    estado: o.status,
    payment_status: o.payment_status,
    metodo_pago: o.payment_method,
    comprobante: o.payment_proof_url,
    creado_en: o.created_at,
    items: (items ?? []).map((it) => ({
      nombre: it.product_name,
      cantidad: it.quantity,
      precio_unit: Number(it.unit_price || 0),
      subtotal: Number(it.subtotal || 0),
      size: it.size,
      color: it.color
    }))
  }
}

const ALLOWED_STATUS = new Set(['pending', 'paid', 'shipped', 'delivered', 'cancelled'])

export async function setOrderStatus(session, orderId, target) {
  if (!ALLOWED_STATUS.has(target)) return { error: 'estado inválido' }
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const now = new Date().toISOString()
  const u = { status: target }
  if (target === 'paid') { u.payment_status = 'paid'; u.payment_verified_at = now }
  if (target === 'shipped') u.shipped_at = now
  if (target === 'delivered') u.delivered_at = now
  const { error } = await db.from('orders').update(u).eq('id', orderId)
  if (error) return { error: error.message }
  logActivity(session, 'pedido_estado', `${orderId} → ${target}`)
  return { ok: true }
}

export async function deleteOrder(session, orderId) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  await db.from('order_items').delete().eq('order_id', orderId)
  const { error } = await db.from('orders').delete().eq('id', orderId)
  if (error) return { error: error.message }
  logActivity(session, 'pedido_eliminado', orderId)
  return { ok: true }
}

// ---------- Log de actividad (quién, cuándo, qué) ----------
export async function logActivity(session, action, detail) {
  try {
    await eco.from('store_activity').insert({
      client_id: session.client_id,
      user_name: session.name,
      action,
      detail: detail || null
    })
  } catch {
    /* el log nunca debe romper la operación */
  }
}

export async function listActivity(session) {
  const { data } = await eco
    .from('store_activity')
    .select('id,user_name,action,detail,created_at')
    .eq('client_id', session.client_id)
    .order('created_at', { ascending: false })
    .limit(60)
  return data ?? []
}

// ---------- Productos (CRUD contra la tienda) ----------
const PROD_FIELDS = ['name', 'description', 'price', 'stock', 'category', 'code', 'is_active']

export async function createProduct(session, body) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  if (!body.name) return { error: 'falta el nombre' }
  const row = {}
  for (const f of PROD_FIELDS) if (body[f] !== undefined) row[f] = body[f]
  row.is_active = row.is_active ?? true
  const { data, error } = await db.from('products').insert(row).select('id').single()
  if (error) return { error: error.message }
  logActivity(session, 'producto_creado', body.name)
  return { ok: true, id: data.id }
}

export async function updateProduct(session, productId, body) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const u = {}
  for (const f of PROD_FIELDS) if (body[f] !== undefined) u[f] = body[f]
  const { error } = await db.from('products').update(u).eq('id', productId)
  if (error) return { error: error.message }
  logActivity(session, 'producto_editado', body.name || productId)
  return { ok: true }
}

export async function deleteProduct(session, productId) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  // Limpia dependencias con FK antes de borrar el producto
  await db.from('product_images').delete().eq('product_id', productId)
  await db.from('product_variants').delete().eq('product_id', productId)
  await db.from('featured_products').delete().eq('product_id', productId)
  const { error } = await db.from('products').delete().eq('id', productId)
  if (error) return { error: error.message }
  logActivity(session, 'producto_eliminado', productId)
  return { ok: true }
}

export async function adjustStock(session, productId, delta, motivo) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const { data: cur, error: e1 } = await db.from('products').select('name,stock').eq('id', productId).single()
  if (e1) return { error: e1.message }
  const nuevo = Math.max(0, (cur.stock ?? 0) + Number(delta || 0))
  const { error } = await db.from('products').update({ stock: nuevo }).eq('id', productId)
  if (error) return { error: error.message }
  logActivity(session, 'stock_ajustado', `${cur.name}: ${cur.stock} → ${nuevo}${motivo ? ` (${motivo})` : ''}`)
  return { ok: true, stock: nuevo }
}

// ---------- Clientes (derivados de los pedidos de la tienda) ----------
export async function storeCustomers(session) {
  const db = await storeDbFor(session.client_id)
  if (!db) return []
  const { data } = await db
    .from('orders')
    .select('customer_name,customer_email,customer_phone,total,created_at')
    .order('created_at', { ascending: false })
    .limit(1000)
  const map = new Map()
  for (const o of data ?? []) {
    const key = (o.customer_phone || o.customer_email || o.customer_name || '').trim().toLowerCase()
    if (!key) continue
    if (!map.has(key)) {
      map.set(key, {
        nombre: o.customer_name,
        email: o.customer_email,
        telefono: o.customer_phone,
        compras: 0,
        total: 0,
        ultima: o.created_at
      })
    }
    const c = map.get(key)
    c.compras += 1
    c.total += Number(o.total || 0)
  }
  return [...map.values()].sort((a, b) => b.compras - a.compras)
}

export async function reprintOrder(session, orderId) {
  const { data: c } = await eco
    .from('print_clients')
    .select('name,store_name,store_web,store_supabase_url,store_service_key')
    .eq('id', session.client_id)
    .single()
  if (!c?.store_supabase_url) return { error: 'tienda no configurada' }
  const db = storeClient(c.store_supabase_url, c.store_service_key)
  const { data: order } = await db.from('orders').select('*').eq('id', orderId).single()
  if (!order) return { error: 'pedido no encontrado' }
  const { data: items } = await db
    .from('order_items')
    .select('product_name,quantity,unit_price,size,color')
    .eq('order_id', orderId)
  const payload = buildOrderPayload(order, items ?? [], c)
  const res = await emitNewOrder(session.client_id, payload)
  return { ok: true, delivery: res }
}

export async function storeProducts(session) {
  const db = await storeDbFor(session.client_id)
  if (!db) return []
  const { data } = await db
    .from('products')
    .select('id,name,code,price,stock,category,description,is_active')
    .order('name')
  return (data ?? []).map((p) => ({
    id: p.id,
    nombre: p.name,
    sku: p.code,
    precio: Number(p.price || 0),
    stock: p.stock,
    categoria: p.category,
    descripcion: p.description,
    activo: p.is_active
  }))
}

export async function storeDashboard(session) {
  const db = await storeDbFor(session.client_id)
  const empty = { ventasHoy: 0, pedidosHoy: 0, pedidosMes: 0, ingresosMes: 0, pagadoMes: 0, totalProductos: 0, stockBajo: [], ultimos: [], ventas7: [] }
  if (!db) return empty
  const now = new Date()
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()
  const sevenAgo = new Date(); sevenAgo.setDate(sevenAgo.getDate() - 6); sevenAgo.setHours(0, 0, 0, 0)

  const [prodRes, recentRes, weekRes, monthRes, prodCount] = await Promise.all([
    db.from('products').select('name,stock'),
    db.from('orders').select('order_number,customer_name,total,status,created_at').order('created_at', { ascending: false }).limit(6),
    db.from('orders').select('total,created_at').gte('created_at', sevenAgo.toISOString()),
    db.from('orders').select('total,payment_status,created_at').gte('created_at', monthStart),
    db.from('products').select('id', { count: 'exact', head: true })
  ])

  const stockBajo = (prodRes.data ?? []).filter((p) => (p.stock ?? 0) < 5).map((p) => ({ nombre: p.name, stock: p.stock })).sort((a, b) => a.stock - b.stock).slice(0, 10)
  const ultimos = (recentRes.data ?? []).map((o) => ({ numero: o.order_number, cliente: o.customer_name, total: Number(o.total || 0), estado: o.status, creado_en: o.created_at }))

  // Días calculados en hora de Bolivia (America/La_Paz), no UTC
  const laPazDay = (d) => new Date(d).toLocaleDateString('en-CA', { timeZone: 'America/La_Paz' })
  const today = laPazDay(Date.now())
  const hoy = (weekRes.data ?? []).filter((o) => laPazDay(o.created_at) === today)
  const ventasHoy = hoy.reduce((a, o) => a + Number(o.total || 0), 0)

  const mes = monthRes.data ?? []
  const ingresosMes = mes.reduce((a, o) => a + Number(o.total || 0), 0)
  const pagadoMes = mes.filter((o) => o.payment_status === 'paid').reduce((a, o) => a + Number(o.total || 0), 0)

  const tot = new Map(), cnt = new Map()
  for (const o of weekRes.data ?? []) {
    const d = laPazDay(o.created_at)
    tot.set(d, (tot.get(d) ?? 0) + Number(o.total || 0))
    cnt.set(d, (cnt.get(d) ?? 0) + 1)
  }
  const ventas7 = []
  for (let i = 6; i >= 0; i--) {
    const d = laPazDay(Date.now() - i * 86400000)
    ventas7.push({ dia: d.slice(5), total: tot.get(d) ?? 0, cantidad: cnt.get(d) ?? 0 })
  }

  return { ventasHoy, pedidosHoy: hoy.length, pedidosMes: mes.length, ingresosMes, pagadoMes, totalProductos: prodCount.count ?? 0, stockBajo, ultimos, ventas7 }
}
