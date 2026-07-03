import crypto from 'crypto'
import { eco, storeClient } from './supabase.js'
import { CONFIG } from './config.js'

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
    .select('id,order_number,customer_name,total,status,payment_method,created_at')
    .order('created_at', { ascending: false })
    .limit(100)
  return (data ?? []).map((o) => ({
    id: o.id,
    numero: o.order_number,
    cliente: o.customer_name,
    total: Number(o.total || 0),
    estado: o.status,
    metodo_pago: o.payment_method,
    creado_en: o.created_at
  }))
}

export async function storeProducts(session) {
  const db = await storeDbFor(session.client_id)
  if (!db) return []
  const { data } = await db
    .from('products')
    .select('id,name,code,price,stock,category')
    .order('name')
  return (data ?? []).map((p) => ({
    id: p.id,
    nombre: p.name,
    sku: p.code,
    precio: Number(p.price || 0),
    stock: p.stock,
    categoria: p.category
  }))
}

export async function storeDashboard(session) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { ventasHoy: 0, pedidosHoy: 0, stockBajo: [], ultimos: [], ventas7: [] }
  const sevenAgo = new Date()
  sevenAgo.setDate(sevenAgo.getDate() - 6)
  sevenAgo.setHours(0, 0, 0, 0)

  const [prodRes, recentRes, weekRes] = await Promise.all([
    db.from('products').select('name,stock'),
    db.from('orders').select('order_number,customer_name,total,status,created_at').order('created_at', { ascending: false }).limit(5),
    db.from('orders').select('total,created_at').gte('created_at', sevenAgo.toISOString())
  ])

  const stockBajo = (prodRes.data ?? [])
    .filter((p) => (p.stock ?? 0) < 5)
    .map((p) => ({ nombre: p.name, stock: p.stock }))
    .sort((a, b) => a.stock - b.stock)
    .slice(0, 10)

  const ultimos = (recentRes.data ?? []).map((o) => ({
    numero: o.order_number,
    cliente: o.customer_name,
    total: Number(o.total || 0),
    estado: o.status,
    creado_en: o.created_at
  }))

  const today = new Date().toISOString().slice(0, 10)
  const hoy = (weekRes.data ?? []).filter((o) => (o.created_at || '').slice(0, 10) === today)
  const ventasHoy = hoy.reduce((a, o) => a + Number(o.total || 0), 0)

  const map = new Map()
  for (const o of weekRes.data ?? []) {
    const d = (o.created_at || '').slice(0, 10)
    map.set(d, (map.get(d) ?? 0) + Number(o.total || 0))
  }
  const ventas7 = []
  for (let i = 6; i >= 0; i--) {
    const dt = new Date()
    dt.setDate(dt.getDate() - i)
    const d = dt.toISOString().slice(0, 10)
    ventas7.push({ dia: d.slice(5), total: map.get(d) ?? 0 })
  }

  return { ventasHoy, pedidosHoy: hoy.length, stockBajo, ultimos, ventas7 }
}
