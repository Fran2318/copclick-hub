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
    .select('id,name,role,avatar,created_at')
    .eq('client_id', session.client_id)
    .order('created_at')
  return data ?? []
}

// Lista pública (solo con el código de acceso): para la pantalla de perfiles
export async function publicUsers(code) {
  const c = await clientByCode(code)
  if (!c) return { error: 'Código de acceso inválido' }
  if (c.status === 'blocked') return { error: 'Esta tienda está bloqueada' }
  const { data } = await eco
    .from('store_users')
    .select('id,name,role,avatar')
    .eq('client_id', c.id)
    .order('created_at')
  return { users: data ?? [] }
}

export async function updateUser(session, userId, body) {
  const self = session.user_id === userId
  if (!self && session.role !== 'admin') return { error: 'Sin permiso' }
  const u = {}
  if (body.avatar !== undefined) {
    if (body.avatar && String(body.avatar).length > 200000) return { error: 'foto de perfil muy pesada' }
    u.avatar = body.avatar || null
  }
  if (body.password) u.password_hash = hashPassword(body.password)
  if (session.role === 'admin') {
    if (body.name) u.name = String(body.name).trim()
    if (body.role) u.role = body.role === 'admin' ? 'admin' : 'user'
  }
  if (!Object.keys(u).length) return { error: 'nada que cambiar' }
  // Nunca dejar la tienda sin admin
  if (u.role === 'user') {
    const { data: cur } = await eco.from('store_users').select('role').eq('id', userId).single()
    if (cur?.role === 'admin') {
      const { count } = await eco
        .from('store_users')
        .select('id', { count: 'exact', head: true })
        .eq('client_id', session.client_id)
        .eq('role', 'admin')
      if ((count ?? 0) <= 1) return { error: 'No podés quitar el único admin' }
    }
  }
  const { error } = await eco.from('store_users').update(u).eq('id', userId).eq('client_id', session.client_id)
  if (error) return { error: error.message.includes('duplicate') ? 'Ya existe un usuario con ese nombre' : error.message }
  logActivity(session, 'usuario_editado', u.name || userId)
  return { ok: true }
}

export async function deleteUser(session, userId) {
  if (session.role !== 'admin') return { error: 'Solo el admin puede eliminar usuarios' }
  if (session.user_id === userId) return { error: 'No podés eliminar tu propio usuario' }
  const { data: u } = await eco
    .from('store_users')
    .select('name,role')
    .eq('id', userId)
    .eq('client_id', session.client_id)
    .single()
  if (!u) return { error: 'usuario no encontrado' }
  if (u.role === 'admin') {
    const { count } = await eco
      .from('store_users')
      .select('id', { count: 'exact', head: true })
      .eq('client_id', session.client_id)
      .eq('role', 'admin')
    if ((count ?? 0) <= 1) return { error: 'No podés eliminar el único admin' }
  }
  const { error } = await eco.from('store_users').delete().eq('id', userId).eq('client_id', session.client_id)
  if (error) return { error: error.message }
  logActivity(session, 'usuario_eliminado', u.name)
  return { ok: true }
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
// Cache de clientes por tienda: evita buscar credenciales (y crear un cliente
// nuevo de supabase-js) en cada request. TTL de 5 min por si se rotan claves.
const DB_TTL = 5 * 60 * 1000
const dbCache = new Map() // client_id -> { db, at }

async function storeDbFor(clientId) {
  const hit = dbCache.get(clientId)
  if (hit && Date.now() - hit.at < DB_TTL) return hit.db
  const { data: c } = await eco
    .from('print_clients')
    .select('store_supabase_url,store_service_key')
    .eq('id', clientId)
    .single()
  if (!c?.store_supabase_url || !c?.store_service_key) return null
  const db = storeClient(c.store_supabase_url, c.store_service_key)
  dbCache.set(clientId, { db, at: Date.now() })
  return db
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
const PROD_FIELDS = ['name', 'description', 'price', 'stock', 'category', 'code', 'is_active', 'wholesale_price']

// Alcance del producto (online / sucursal / ambas) — vive en el ecosistema,
// porque el esquema de la tienda no se puede tocar.
async function saveScope(session, productId, alcance, sucursalId) {
  if (!alcance || !['online', 'sucursal', 'ambas'].includes(alcance)) return
  await eco.from('store_product_meta').upsert(
    {
      client_id: session.client_id,
      product_id: String(productId),
      scope: alcance,
      branch_id: alcance === 'sucursal' ? sucursalId || null : null
    },
    { onConflict: 'client_id,product_id' }
  )
}

export async function createProduct(session, body) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  if (!body.name) return { error: 'falta el nombre' }
  const row = {}
  for (const f of PROD_FIELDS) if (body[f] !== undefined) row[f] = body[f]
  row.is_active = row.is_active ?? true
  // Producto solo de sucursal: nunca visible en la web
  if (body.alcance === 'sucursal') row.is_active = false
  const { data, error } = await db.from('products').insert(row).select('id').single()
  if (error) return { error: error.message }
  await saveScope(session, data.id, body.alcance, body.sucursal_id)
  logActivity(session, 'producto_creado', body.name)
  return { ok: true, id: data.id }
}

export async function updateProduct(session, productId, body) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const u = {}
  for (const f of PROD_FIELDS) if (body[f] !== undefined) u[f] = body[f]
  if (body.alcance === 'sucursal') u.is_active = false
  if (Object.keys(u).length) {
    const { error } = await db.from('products').update(u).eq('id', productId)
    if (error) return { error: error.message }
  }
  await saveScope(session, productId, body.alcance, body.sucursal_id)
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
  await eco.from('store_product_meta').delete().eq('client_id', session.client_id).eq('product_id', String(productId))
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

// ---------- Variantes (tallas y colores, en el Supabase de la tienda) ----------
const VAR_FIELDS = ['sku', 'size', 'color', 'color_code', 'stock', 'price_adjustment', 'is_active']

export async function saveVariant(session, productId, body) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const row = {}
  for (const f of VAR_FIELDS) if (body[f] !== undefined) row[f] = body[f]
  if (body.id) {
    const { error } = await db.from('product_variants').update(row).eq('id', body.id).eq('product_id', productId)
    if (error) return { error: error.message }
    logActivity(session, 'variante_editada', `${body.size || ''} ${body.color || ''}`.trim() || String(body.id))
    return { ok: true, id: body.id }
  }
  if (!row.size && !row.color) return { error: 'poné al menos talla o color' }
  row.is_active = row.is_active ?? true
  const { data, error } = await db
    .from('product_variants')
    .insert({ ...row, product_id: productId })
    .select('id')
    .single()
  if (error) return { error: error.message }
  logActivity(session, 'variante_creada', `${row.size || ''} ${row.color || ''}`.trim())
  return { ok: true, id: data.id }
}

export async function deleteVariant(session, variantId) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const { error } = await db.from('product_variants').delete().eq('id', variantId)
  if (error) return { error: error.message }
  logActivity(session, 'variante_eliminada', String(variantId))
  return { ok: true }
}

// ---------- Fotos de producto (Storage de la tienda, bucket "products") ----------
const imgPathFromUrl = (url) => {
  const m = String(url).match(/\/object\/public\/products\/(.+)$/)
  return m ? decodeURIComponent(m[1]) : null
}

async function getImages(db, productId) {
  const { data } = await db.from('products').select('images,name').eq('id', productId).single()
  return { imgs: Array.isArray(data?.images) ? data.images : [], name: data?.name }
}

export async function addProductImage(session, productId, body) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const m = String(body.data || '').match(/^data:(image\/[a-z+.-]+);base64,(.+)$/i)
  if (!m) return { error: 'imagen inválida' }
  const buf = Buffer.from(m[2], 'base64')
  if (buf.length > 4 * 1024 * 1024) return { error: 'imagen muy pesada (máx. 4 MB)' }
  const ext = (m[1].split('/')[1] || 'png').replace('jpeg', 'jpg').replace(/[^a-z0-9]/g, '')
  const path = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${ext}`
  const { error: eUp } = await db.storage.from('products').upload(path, buf, { contentType: m[1] })
  if (eUp) return { error: eUp.message }
  const url = db.storage.from('products').getPublicUrl(path).data.publicUrl

  const { imgs, name } = await getImages(db, productId)
  const nuevas = [...imgs, url]
  const { error } = await db.from('products').update({ images: nuevas }).eq('id', productId)
  if (error) return { error: error.message }
  // Mantener product_images en sincronía (la web de la tienda también la usa)
  await db.from('product_images').insert({
    product_id: productId,
    image_url: url,
    is_main: nuevas.length === 1,
    display_order: nuevas.length - 1
  })
  logActivity(session, 'foto_agregada', name || productId)
  return { ok: true, url, imagenes: nuevas }
}

export async function deleteProductImage(session, productId, url) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const { imgs, name } = await getImages(db, productId)
  const nuevas = imgs.filter((u) => u !== url)
  const { error } = await db.from('products').update({ images: nuevas }).eq('id', productId)
  if (error) return { error: error.message }
  await db.from('product_images').delete().eq('product_id', productId).eq('image_url', url)
  const path = imgPathFromUrl(url)
  if (path) await db.storage.from('products').remove([path])
  logActivity(session, 'foto_eliminada', name || productId)
  return { ok: true, imagenes: nuevas }
}

export async function setMainImage(session, productId, url) {
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }
  const { imgs } = await getImages(db, productId)
  if (!imgs.includes(url)) return { error: 'esa foto no es del producto' }
  const nuevas = [url, ...imgs.filter((u) => u !== url)]
  const { error } = await db.from('products').update({ images: nuevas }).eq('id', productId)
  if (error) return { error: error.message }
  await db.from('product_images').update({ is_main: false }).eq('product_id', productId)
  await db.from('product_images').update({ is_main: true }).eq('product_id', productId).eq('image_url', url)
  return { ok: true, imagenes: nuevas }
}

// ---------- Sucursales (viven en el Supabase del ecosistema, por client_id) ----------
export async function listBranches(session) {
  const { data } = await eco
    .from('store_branches')
    .select('id,name,address,phone,is_active,created_at')
    .eq('client_id', session.client_id)
    .order('created_at')
  return data ?? []
}

export async function saveBranch(session, body) {
  if (!body.name) return { error: 'falta el nombre' }
  const row = { name: body.name, address: body.address || null, phone: body.phone || null }
  if (body.is_active !== undefined) row.is_active = !!body.is_active
  if (body.id) {
    const { error } = await eco
      .from('store_branches')
      .update(row)
      .eq('id', body.id)
      .eq('client_id', session.client_id)
    if (error) return { error: error.message }
    logActivity(session, 'sucursal_editada', body.name)
    return { ok: true }
  }
  const { data, error } = await eco
    .from('store_branches')
    .insert({ ...row, client_id: session.client_id })
    .select('id')
    .single()
  if (error) return { error: error.message }
  logActivity(session, 'sucursal_creada', body.name)
  return { ok: true, id: data.id }
}

export async function deleteBranch(session, branchId) {
  await eco.from('store_branch_stock').delete().eq('branch_id', branchId).eq('client_id', session.client_id)
  const { error } = await eco
    .from('store_branches')
    .delete()
    .eq('id', branchId)
    .eq('client_id', session.client_id)
  if (error) return { error: error.message }
  logActivity(session, 'sucursal_eliminada', branchId)
  return { ok: true }
}

// ---------- Stock físico por sucursal (y por variante: variant_key = "talla|color") ----------
export async function getBranchStock(session) {
  const { data } = await eco
    .from('store_branch_stock')
    .select('branch_id,product_id,variant_key,quantity')
    .eq('client_id', session.client_id)
  return data ?? []
}

export async function adjustBranchStock(session, body) {
  const { branch_id, product_id, delta, nombre } = body
  if (!branch_id || !product_id) return { error: 'faltan datos' }
  const vk = body.variant_key ? String(body.variant_key) : ''
  const { data: cur } = await eco
    .from('store_branch_stock')
    .select('id,quantity')
    .eq('branch_id', branch_id)
    .eq('product_id', product_id)
    .eq('variant_key', vk)
    .maybeSingle()
  const prev = cur?.quantity ?? 0
  // "set" pone un valor exacto; "delta" suma o resta
  const nuevo =
    body.set !== undefined && body.set !== null
      ? Math.max(0, Math.round(Number(body.set) || 0))
      : Math.max(0, prev + Number(delta || 0))
  const { error } = await eco.from('store_branch_stock').upsert(
    {
      client_id: session.client_id,
      branch_id,
      product_id,
      variant_key: vk,
      quantity: nuevo,
      updated_at: new Date().toISOString(),
      updated_by: session.name
    },
    { onConflict: 'branch_id,product_id,variant_key' }
  )
  if (error) return { error: error.message }
  const etiqueta = vk ? `${nombre || product_id} (${vk.replace('|', ' · ')})` : nombre || product_id
  logActivity(session, 'stock_fisico', `${etiqueta}: ${prev} → ${nuevo}`)
  return { ok: true, quantity: nuevo }
}

// ---------- Transferencias entre sucursales ----------
export async function listTransfers(session) {
  const { data } = await eco
    .from('store_transfers')
    .select('id,product_name,variant_key,from_branch_id,to_branch_id,quantity,transferred_by,transferred_at')
    .eq('client_id', session.client_id)
    .order('transferred_at', { ascending: false })
    .limit(30)
  return data ?? []
}

export async function transferStock(session, body) {
  const { product_id, nombre, from_branch_id, to_branch_id, quantity } = body
  const qty = Number(quantity || 0)
  const vk = body.variant_key ? String(body.variant_key) : ''
  if (!product_id || !from_branch_id || !to_branch_id || qty <= 0) return { error: 'datos incompletos' }
  if (from_branch_id === to_branch_id) return { error: 'origen y destino son la misma sucursal' }

  const { data: origen } = await eco
    .from('store_branch_stock')
    .select('quantity')
    .eq('branch_id', from_branch_id)
    .eq('product_id', product_id)
    .eq('variant_key', vk)
    .maybeSingle()
  const disp = origen?.quantity ?? 0
  if (qty > disp) return { error: `stock insuficiente en origen (hay ${disp})` }

  const r1 = await adjustBranchStock(session, { branch_id: from_branch_id, product_id, variant_key: vk, delta: -qty, nombre })
  if (r1.error) return r1
  const r2 = await adjustBranchStock(session, { branch_id: to_branch_id, product_id, variant_key: vk, delta: qty, nombre })
  if (r2.error) return r2

  await eco.from('store_transfers').insert({
    client_id: session.client_id,
    product_id,
    product_name: nombre || null,
    variant_key: vk || null,
    from_branch_id,
    to_branch_id,
    quantity: qty,
    transferred_by: session.name
  })
  logActivity(session, 'transferencia', `${nombre || product_id}${vk ? ` (${vk.replace('|', ' · ')})` : ''} ×${qty}`)
  return { ok: true }
}

// ---------- Caja: ventas físicas en el local ----------
// Afectan SOLO el stock físico de la sucursal; el stock online no se toca.
const METODOS_CAJA = new Set(['efectivo', 'tarjeta', 'transferencia'])

async function decBranchStock(clientId, branchId, productId, qty, vk = '') {
  const { data: cur } = await eco
    .from('store_branch_stock')
    .select('quantity')
    .eq('branch_id', branchId)
    .eq('product_id', productId)
    .eq('variant_key', vk)
    .maybeSingle()
  const nuevo = Math.max(0, (cur?.quantity ?? 0) - qty)
  await eco.from('store_branch_stock').upsert(
    {
      client_id: clientId,
      branch_id: branchId,
      product_id: productId,
      variant_key: vk,
      quantity: nuevo,
      updated_at: new Date().toISOString(),
      updated_by: 'caja'
    },
    { onConflict: 'branch_id,product_id,variant_key' }
  )
}

export async function createSale(session, body) {
  const items = Array.isArray(body.items) ? body.items.slice(0, 100) : []
  if (!items.length) return { error: 'la venta no tiene productos' }
  const metodo = METODOS_CAJA.has(body.payment_method) ? body.payment_method : null
  if (!metodo) return { error: 'método de pago inválido' }

  let branch = null
  if (body.branch_id) {
    const { data } = await eco
      .from('store_branches')
      .select('id,name')
      .eq('id', body.branch_id)
      .eq('client_id', session.client_id)
      .maybeSingle()
    if (!data) return { error: 'sucursal inválida' }
    branch = data
  }

  const clean = []
  let total = 0
  for (const it of items) {
    const nombre = String(it.nombre || '').trim()
    const qty = Math.round(Number(it.cantidad || 0))
    const price = Number(it.precio || 0)
    if (!nombre || qty <= 0 || price < 0) return { error: `ítem inválido: ${nombre || '(sin nombre)'}` }
    clean.push({
      product_id: it.product_id ? String(it.product_id) : null,
      product_name: nombre,
      quantity: qty,
      unit_price: price,
      subtotal: Math.round(qty * price * 100) / 100,
      size: it.size ? String(it.size) : null,
      color: it.color ? String(it.color) : null
    })
    total += qty * price
  }
  total = Math.round(total * 100) / 100
  const pagado = metodo === 'efectivo' ? Number(body.monto_pagado || 0) : total
  if (metodo === 'efectivo' && pagado < total) return { error: 'el monto pagado no cubre el total' }
  const cambio = Math.round((pagado - total) * 100) / 100

  const { count } = await eco
    .from('store_sales')
    .select('id', { count: 'exact', head: true })
    .eq('client_id', session.client_id)
  const numero = 'F-' + String((count ?? 0) + 1).padStart(4, '0')

  const { data: sale, error } = await eco
    .from('store_sales')
    .insert({
      client_id: session.client_id,
      sale_number: numero,
      branch_id: branch?.id ?? null,
      branch_name: branch?.name ?? null,
      payment_method: metodo,
      total,
      monto_pagado: pagado,
      cambio,
      sold_by: session.name
    })
    .select('id')
    .single()
  if (error) return { error: error.message }

  const { error: e2 } = await eco
    .from('store_sale_items')
    .insert(clean.map((c) => ({ ...c, sale_id: sale.id, client_id: session.client_id })))
  if (e2) return { error: e2.message }

  if (branch) {
    for (const c of clean) {
      if (!c.product_id) continue
      const vk = [c.size, c.color].filter(Boolean).join('|')
      await decBranchStock(session.client_id, branch.id, c.product_id, c.quantity, vk)
    }
  }
  logActivity(session, 'venta_fisica', `${numero} · Bs. ${total} (${metodo}${branch ? ' · ' + branch.name : ''})`)
  return { ok: true, id: sale.id, numero, total, cambio }
}

export async function listSales(session) {
  const { data: sales } = await eco
    .from('store_sales')
    .select('id,sale_number,branch_id,branch_name,payment_method,total,monto_pagado,cambio,sold_by,created_at')
    .eq('client_id', session.client_id)
    .order('created_at', { ascending: false })
    .limit(100)
  const ids = (sales ?? []).map((s) => s.id)
  const items = []
  for (let i = 0; i < ids.length; i += 100) {
    const { data: chunk } = await eco
      .from('store_sale_items')
      .select('sale_id,product_name,quantity,unit_price,subtotal,size,color')
      .in('sale_id', ids.slice(i, i + 100))
    items.push(...(chunk ?? []))
  }
  const bySale = new Map()
  for (const it of items) {
    if (!bySale.has(it.sale_id)) bySale.set(it.sale_id, [])
    bySale.get(it.sale_id).push(it)
  }
  return (sales ?? []).map((s) => ({ ...s, items: bySale.get(s.id) ?? [] }))
}

// ---------- Finanzas: datos del usuario (persistentes) + indicadores ----------
const laPazMonth = (d) =>
  new Date(d).toLocaleDateString('en-CA', { timeZone: 'America/La_Paz' }).slice(0, 7)

// TIR mensual por bisección, anualizada. flows[0] suele ser negativo (inversión).
function irrAnual(flows) {
  if (flows.length < 2) return null
  const npv = (r) => flows.reduce((a, f, i) => a + f / Math.pow(1 + r, i), 0)
  let lo = -0.95, hi = 5
  if (npv(lo) * npv(hi) > 0) return null
  for (let i = 0; i < 120; i++) {
    const mid = (lo + hi) / 2
    if (npv(lo) * npv(mid) <= 0) hi = mid
    else lo = mid
  }
  const rm = (lo + hi) / 2
  return Math.pow(1 + rm, 12) - 1
}

export async function saveFinance(session, data) {
  const { error } = await eco.from('store_finance').upsert(
    {
      client_id: session.client_id,
      data: data || {},
      updated_at: new Date().toISOString(),
      updated_by: session.name
    },
    { onConflict: 'client_id' }
  )
  if (error) return { error: error.message }
  logActivity(session, 'finanzas_actualizadas', 'datos de indicadores')
  return getFinance(session)
}

export async function getFinance(session) {
  const { data: row } = await eco
    .from('store_finance')
    .select('data,updated_at,updated_by')
    .eq('client_id', session.client_id)
    .maybeSingle()
  const inputs = row?.data ?? {}

  const db = await storeDbFor(session.client_id)
  if (!db) return { inputs, meta: row ?? null, indicators: null }

  // Últimos 12 meses de pedidos válidos (excluye cancelados)
  const desde = new Date()
  desde.setMonth(desde.getMonth() - 12)
  const { data: orders } = await db
    .from('orders')
    .select('id,total,status,created_at')
    .gte('created_at', desde.toISOString())
    .neq('status', 'cancelled')

  // Ítems de esos pedidos (en lotes) + costos del catálogo
  const ids = (orders ?? []).map((o) => o.id)
  const items = []
  for (let i = 0; i < ids.length; i += 100) {
    const { data: chunk } = await db
      .from('order_items')
      .select('order_id,product_id,quantity')
      .in('order_id', ids.slice(i, i + 100))
    items.push(...(chunk ?? []))
  }
  const { data: prods } = await db.from('products').select('id,wholesale_price')
  const costMap = new Map((prods ?? []).map((p) => [String(p.id), Number(p.wholesale_price || 0)]))
  const orderMonth = new Map((orders ?? []).map((o) => [o.id, laPazMonth(o.created_at)]))

  // Ventas físicas de Caja (viven en el ecosistema, no en la tienda)
  const { data: fisSales } = await eco
    .from('store_sales')
    .select('id,total,created_at')
    .eq('client_id', session.client_id)
    .gte('created_at', desde.toISOString())
  const fisIds = (fisSales ?? []).map((s) => s.id)
  const fisItems = []
  for (let i = 0; i < fisIds.length; i += 100) {
    const { data: chunk } = await eco
      .from('store_sale_items')
      .select('sale_id,product_id,quantity')
      .in('sale_id', fisIds.slice(i, i + 100))
    fisItems.push(...(chunk ?? []))
  }
  const saleMonth = new Map((fisSales ?? []).map((s) => [s.id, laPazMonth(s.created_at)]))

  // Buckets mensuales: ingresos, COGS (costo de lo vendido), cobertura de costos
  const meses = new Map() // 'YYYY-MM' -> { ingresos, cogs }
  let qtyTotal = 0, qtyConCosto = 0
  for (const o of orders ?? []) {
    const m = laPazMonth(o.created_at)
    if (!meses.has(m)) meses.set(m, { ingresos: 0, cogs: 0 })
    meses.get(m).ingresos += Number(o.total || 0)
  }
  for (const s of fisSales ?? []) {
    const m = laPazMonth(s.created_at)
    if (!meses.has(m)) meses.set(m, { ingresos: 0, cogs: 0 })
    meses.get(m).ingresos += Number(s.total || 0)
  }
  for (const it of items) {
    const m = orderMonth.get(it.order_id)
    if (!m || !meses.has(m)) continue
    const cost = costMap.get(String(it.product_id)) ?? 0
    const q = Number(it.quantity || 0)
    qtyTotal += q
    if (cost > 0) {
      qtyConCosto += q
      meses.get(m).cogs += cost * q
    }
  }
  for (const it of fisItems) {
    const m = saleMonth.get(it.sale_id)
    if (!m || !meses.has(m)) continue
    const cost = (it.product_id && costMap.get(String(it.product_id))) || 0
    const q = Number(it.quantity || 0)
    qtyTotal += q
    if (cost > 0) {
      qtyConCosto += q
      meses.get(m).cogs += cost * q
    }
  }

  const gastosMes =
    Number(inputs.alquiler || 0) + Number(inputs.sueldos || 0) + Number(inputs.servicios || 0) +
    Number(inputs.marketing || 0) + Number(inputs.otros || 0)

  // Serie mensual ordenada (últimos 12)
  const mesesOrd = [...meses.keys()].sort()
  const serie = mesesOrd.map((m) => {
    const b = meses.get(m)
    const bruto = b.ingresos - b.cogs
    return { mes: m, ingresos: Math.round(b.ingresos), cogs: Math.round(b.cogs), bruto: Math.round(bruto), ban: Math.round(bruto - gastosMes) }
  })

  const mesActual = laPazMonth(Date.now())
  const actual = serie.find((s) => s.mes === mesActual) ?? { ingresos: 0, cogs: 0, bruto: 0, ban: -gastosMes }

  const ingresosTot = serie.reduce((a, s) => a + s.ingresos, 0)
  const brutoTot = serie.reduce((a, s) => a + s.bruto, 0)
  const margenBrutoPct = ingresosTot > 0 ? Math.round((brutoTot / ingresosTot) * 100) : null
  const banTot = serie.reduce((a, s) => a + s.ban, 0)
  const margenNetoPct = ingresosTot > 0 ? Math.round((banTot / ingresosTot) * 100) : null

  // Punto de equilibrio: ventas necesarias para cubrir gastos con el margen bruto actual
  const puntoEquilibrio =
    gastosMes > 0 && margenBrutoPct && margenBrutoPct > 0
      ? Math.round(gastosMes / (margenBrutoPct / 100))
      : null

  const nPedidos = (orders ?? []).length + (fisSales ?? []).length
  const ticketPromedio = nPedidos > 0 ? Math.round(ingresosTot / nPedidos) : null

  // TIR y ROI: requieren inversión inicial + fecha
  let tir = null, roi = null, mesesDesdeInversion = null
  const inv = Number(inputs.inversion || 0)
  if (inv > 0 && inputs.fecha_inversion) {
    const invMonth = String(inputs.fecha_inversion).slice(0, 7)
    const flujoMeses = mesesOrd.filter((m) => m >= invMonth)
    mesesDesdeInversion = flujoMeses.length
    const flows = [-inv, ...flujoMeses.map((m) => serie.find((s) => s.mes === m)?.ban ?? -gastosMes)]
    tir = irrAnual(flows)
    const acumulado = flujoMeses.reduce((a, m) => a + (serie.find((s) => s.mes === m)?.ban ?? 0), 0)
    roi = Math.round((acumulado / inv) * 100)
  }

  return {
    inputs,
    meta: row ? { updated_at: row.updated_at, updated_by: row.updated_by } : null,
    indicators: {
      gastosMes,
      banMesActual: actual.ban,
      margenBrutoPct,
      margenNetoPct,
      puntoEquilibrio,
      ticketPromedio,
      tirAnualPct: tir === null ? null : Math.round(tir * 100),
      roiPct: roi,
      mesesDesdeInversion,
      costCoveragePct: qtyTotal > 0 ? Math.round((qtyConCosto / qtyTotal) * 100) : 0,
      serie: serie.slice(-6)
    }
  }
}

// ---------- Importación de base de datos (productos desde Excel/CSV) ----------
export async function importProducts(session, body) {
  const rows = Array.isArray(body.rows) ? body.rows.slice(0, 2000) : []
  if (!rows.length) return { error: 'sin filas para importar' }
  const db = await storeDbFor(session.client_id)
  if (!db) return { error: 'tienda no configurada' }

  const { data: existing } = await db.from('products').select('id,name,code')
  const byCode = new Map()
  const byName = new Map()
  for (const p of existing ?? []) {
    if (p.code) byCode.set(String(p.code).trim().toLowerCase(), p.id)
    if (p.name) byName.set(String(p.name).trim().toLowerCase(), p.id)
  }

  let created = 0, updated = 0
  const errors = []
  const toInsert = []

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]
    const name = String(r.name || '').trim()
    if (!name) {
      errors.push(`Fila ${i + 2}: sin nombre de producto`)
      continue
    }
    const row = {
      name,
      price: Number(r.price || 0),
      stock: Math.max(0, Math.round(Number(r.stock || 0))),
      wholesale_price: Number(r.cost || 0),
      category: r.category ? String(r.category).trim() : null,
      code: r.code ? String(r.code).trim() : null
    }
    const id =
      (row.code && byCode.get(row.code.toLowerCase())) || byName.get(name.toLowerCase()) || null
    if (id) {
      const { error } = await db.from('products').update(row).eq('id', id)
      if (error) errors.push(`Fila ${i + 2} (${name}): ${error.message}`)
      else updated++
    } else {
      toInsert.push({ ...row, is_active: true })
    }
  }

  for (let i = 0; i < toInsert.length; i += 100) {
    const chunk = toInsert.slice(i, i + 100)
    const { error } = await db.from('products').insert(chunk)
    if (error) errors.push(`Lote de nuevos: ${error.message}`)
    else created += chunk.length
  }

  await eco.from('store_imports').insert({
    client_id: session.client_id,
    filename: body.filename || 'archivo',
    rows_processed: rows.length,
    rows_succeeded: created + updated,
    rows_failed: errors.length,
    errors: errors.slice(0, 50),
    imported_by: session.name
  })
  logActivity(session, 'importacion', `${body.filename || 'archivo'}: ${created} nuevos, ${updated} actualizados, ${errors.length} errores`)
  return { ok: true, created, updated, failed: errors.length, errors: errors.slice(0, 20) }
}

export async function listImports(session) {
  const { data } = await eco
    .from('store_imports')
    .select('id,filename,rows_processed,rows_succeeded,rows_failed,imported_by,imported_at')
    .eq('client_id', session.client_id)
    .order('imported_at', { ascending: false })
    .limit(20)
  return data ?? []
}

// ---------- Base de datos personalizada (tablas propias del usuario) ----------
const MAX_ROWS_TABLE = 5000
const COL_TYPES = ['text', 'number', 'date', 'boolean', 'currency', 'email', 'phone', 'url']

function cleanColumns(cols) {
  if (!Array.isArray(cols)) return []
  return cols.slice(0, 40).map((c, i) => ({
    key: String(c.key || 'c' + i).slice(0, 40),
    name: String(c.name || 'Columna ' + (i + 1)).slice(0, 60),
    type: COL_TYPES.includes(c.type) ? c.type : 'text',
    required: !!c.required,
    unique: !!c.unique
  }))
}

export async function listTables(session) {
  const { data } = await eco
    .from('store_custom_tables')
    .select('id,name,description,columns,created_by,created_at')
    .eq('client_id', session.client_id)
    .order('created_at')
  const tables = data ?? []
  for (const t of tables) {
    const { count } = await eco
      .from('store_custom_rows')
      .select('id', { count: 'exact', head: true })
      .eq('table_id', t.id)
    t.rows = count ?? 0
  }
  return tables
}

export async function saveTable(session, body) {
  const name = String(body.name || '').trim()
  if (!name) return { error: 'falta el nombre de la tabla' }
  const columns = cleanColumns(body.columns)
  if (!columns.length) return { error: 'agregá al menos una columna' }
  const row = { name, description: body.description || null, columns }
  if (body.id) {
    const { error } = await eco
      .from('store_custom_tables')
      .update(row)
      .eq('id', body.id)
      .eq('client_id', session.client_id)
    if (error) return { error: error.message }
    logActivity(session, 'tabla_editada', name)
    return { ok: true, id: body.id }
  }
  const { data, error } = await eco
    .from('store_custom_tables')
    .insert({ ...row, client_id: session.client_id, created_by: session.name })
    .select('id')
    .single()
  if (error) return { error: error.message }
  logActivity(session, 'tabla_creada', name)
  return { ok: true, id: data.id }
}

export async function deleteTable(session, tableId) {
  const { error } = await eco
    .from('store_custom_tables')
    .delete()
    .eq('id', tableId)
    .eq('client_id', session.client_id)
  if (error) return { error: error.message }
  logActivity(session, 'tabla_eliminada', tableId)
  return { ok: true }
}

async function tableFor(session, tableId) {
  const { data } = await eco
    .from('store_custom_tables')
    .select('id,columns')
    .eq('id', tableId)
    .eq('client_id', session.client_id)
    .maybeSingle()
  return data
}

async function violaUnicos(tableId, columns, data, excludeId) {
  for (const c of columns) {
    if (!c.unique) continue
    const v = data?.[c.key]
    if (v === undefined || v === null || v === '') continue
    let q = eco
      .from('store_custom_rows')
      .select('id', { count: 'exact', head: true })
      .eq('table_id', tableId)
      .eq('data->>' + c.key, String(v))
    if (excludeId) q = q.neq('id', excludeId)
    const { count } = await q
    if ((count ?? 0) > 0) return `"${c.name}" debe ser único: ya existe "${v}"`
  }
  return null
}

export async function listRows(session, tableId) {
  const t = await tableFor(session, tableId)
  if (!t) return { error: 'tabla no encontrada' }
  const { data } = await eco
    .from('store_custom_rows')
    .select('id,data,created_at,updated_at')
    .eq('table_id', tableId)
    .order('created_at')
    .limit(MAX_ROWS_TABLE)
  return data ?? []
}

export async function insertRows(session, tableId, body) {
  const t = await tableFor(session, tableId)
  if (!t) return { error: 'tabla no encontrada' }
  const rows = Array.isArray(body.rows) ? body.rows.slice(0, 2000) : body.data ? [body.data] : []
  if (!rows.length) return { error: 'sin datos' }
  const { count } = await eco
    .from('store_custom_rows')
    .select('id', { count: 'exact', head: true })
    .eq('table_id', tableId)
  if ((count ?? 0) + rows.length > MAX_ROWS_TABLE) return { error: `máximo ${MAX_ROWS_TABLE} filas por tabla` }
  if (rows.length === 1) {
    const err = await violaUnicos(tableId, t.columns ?? [], rows[0], null)
    if (err) return { error: err }
  }
  let ok = 0
  for (let i = 0; i < rows.length; i += 200) {
    const chunk = rows.slice(i, i + 200).map((d) => ({ table_id: tableId, client_id: session.client_id, data: d || {} }))
    const { error } = await eco.from('store_custom_rows').insert(chunk)
    if (error) return { error: error.message, inserted: ok }
    ok += chunk.length
  }
  return { ok: true, inserted: ok }
}

export async function updateRow(session, rowId, body) {
  const { data: r } = await eco
    .from('store_custom_rows')
    .select('table_id')
    .eq('id', rowId)
    .eq('client_id', session.client_id)
    .maybeSingle()
  if (!r) return { error: 'registro no encontrado' }
  const t = await tableFor(session, r.table_id)
  const err = await violaUnicos(r.table_id, t?.columns ?? [], body.data ?? {}, rowId)
  if (err) return { error: err }
  const { error } = await eco
    .from('store_custom_rows')
    .update({ data: body.data ?? {}, updated_at: new Date().toISOString() })
    .eq('id', rowId)
  if (error) return { error: error.message }
  return { ok: true }
}

export async function deleteRow(session, rowId) {
  const { error } = await eco.from('store_custom_rows').delete().eq('id', rowId).eq('client_id', session.client_id)
  if (error) return { error: error.message }
  return { ok: true }
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
  const [{ data }, { data: vars }, { data: metas }] = await Promise.all([
    db
      .from('products')
      .select('id,name,code,price,stock,category,description,is_active,wholesale_price,images')
      .order('name'),
    db
      .from('product_variants')
      .select('id,product_id,sku,size,color,color_code,stock,price_adjustment,is_active')
      .order('id'),
    eco.from('store_product_meta').select('product_id,scope,branch_id').eq('client_id', session.client_id)
  ])
  const metaMap = new Map((metas ?? []).map((m) => [String(m.product_id), m]))
  const varMap = new Map()
  for (const v of vars ?? []) {
    const k = String(v.product_id)
    if (!varMap.has(k)) varMap.set(k, [])
    varMap.get(k).push(v)
  }
  // La primera imagen del producto (si hay) como miniatura para la Caja
  const thumb = (imgs) => {
    if (!Array.isArray(imgs) || !imgs.length) return null
    const f = imgs[0]
    return typeof f === 'string' ? f : f?.url || f?.image_url || null
  }
  return (data ?? []).map((p) => ({
    id: p.id,
    nombre: p.name,
    sku: p.code,
    precio: Number(p.price || 0),
    costo: Number(p.wholesale_price || 0),
    stock: p.stock,
    categoria: p.category,
    descripcion: p.description,
    activo: p.is_active,
    imagen: thumb(p.images),
    imagenes: Array.isArray(p.images) ? p.images : [],
    variantes: varMap.get(String(p.id)) ?? [],
    alcance: metaMap.get(String(p.id))?.scope ?? 'ambas',
    sucursal_id: metaMap.get(String(p.id))?.branch_id ?? null
  }))
}

export async function storeDashboard(session) {
  const db = await storeDbFor(session.client_id)
  const empty = { ventasHoy: 0, pedidosHoy: 0, pedidosMes: 0, ingresosMes: 0, pagadoMes: 0, totalProductos: 0, stockBajo: [], ultimos: [], ventas7: [] }
  if (!db) return empty
  const now = new Date()
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()
  const sevenAgo = new Date(); sevenAgo.setDate(sevenAgo.getDate() - 6); sevenAgo.setHours(0, 0, 0, 0)

  // Ventas físicas de Caja: se traen desde el rango más antiguo (mes o 7 días)
  const desdeVentas = new Date(Math.min(new Date(monthStart).getTime(), sevenAgo.getTime())).toISOString()
  const [prodRes, recentRes, weekRes, monthRes, prodCount, fisicoRes, cajaRes] = await Promise.all([
    db.from('products').select('name,stock,price,wholesale_price'),
    db.from('orders').select('order_number,customer_name,total,status,created_at').order('created_at', { ascending: false }).limit(6),
    db.from('orders').select('total,created_at').gte('created_at', sevenAgo.toISOString()),
    db.from('orders').select('total,payment_status,created_at').gte('created_at', monthStart),
    db.from('products').select('id', { count: 'exact', head: true }),
    eco.from('store_branch_stock').select('quantity').eq('client_id', session.client_id),
    eco.from('store_sales').select('total,created_at').eq('client_id', session.client_id).gte('created_at', desdeVentas)
  ])

  const stockBajo = (prodRes.data ?? []).filter((p) => (p.stock ?? 0) < 5).map((p) => ({ nombre: p.name, stock: p.stock })).sort((a, b) => a.stock - b.stock).slice(0, 10)
  const ultimos = (recentRes.data ?? []).map((o) => ({ numero: o.order_number, cliente: o.customer_name, total: Number(o.total || 0), estado: o.status, creado_en: o.created_at }))

  // Días calculados en hora de Bolivia (America/La_Paz), no UTC
  const laPazDay = (d) => new Date(d).toLocaleDateString('en-CA', { timeZone: 'America/La_Paz' })
  const today = laPazDay(Date.now())
  const caja = cajaRes.data ?? []
  const hoy = (weekRes.data ?? []).filter((o) => laPazDay(o.created_at) === today)
  const cajaHoy = caja.filter((s) => laPazDay(s.created_at) === today)
  const ventasHoy =
    hoy.reduce((a, o) => a + Number(o.total || 0), 0) + cajaHoy.reduce((a, s) => a + Number(s.total || 0), 0)

  const mes = monthRes.data ?? []
  const cajaMes = caja.filter((s) => new Date(s.created_at).getTime() >= new Date(monthStart).getTime())
  const cajaMesTotal = cajaMes.reduce((a, s) => a + Number(s.total || 0), 0)
  const ingresosMes = mes.reduce((a, o) => a + Number(o.total || 0), 0) + cajaMesTotal
  // Las ventas de caja siempre están cobradas
  const pagadoMes =
    mes.filter((o) => o.payment_status === 'paid').reduce((a, o) => a + Number(o.total || 0), 0) + cajaMesTotal

  const tot = new Map(), cnt = new Map()
  for (const o of weekRes.data ?? []) {
    const d = laPazDay(o.created_at)
    tot.set(d, (tot.get(d) ?? 0) + Number(o.total || 0))
    cnt.set(d, (cnt.get(d) ?? 0) + 1)
  }
  for (const s of caja) {
    if (new Date(s.created_at).getTime() < sevenAgo.getTime()) continue
    const d = laPazDay(s.created_at)
    tot.set(d, (tot.get(d) ?? 0) + Number(s.total || 0))
    cnt.set(d, (cnt.get(d) ?? 0) + 1)
  }
  const ventas7 = []
  for (let i = 6; i >= 0; i--) {
    const d = laPazDay(Date.now() - i * 86400000)
    ventas7.push({ dia: d.slice(5), total: tot.get(d) ?? 0, cantidad: cnt.get(d) ?? 0 })
  }

  // Stock online total (catálogo) + stock físico total (todas las sucursales)
  const stockOnlineTotal = (prodRes.data ?? []).reduce((a, p) => a + (p.stock ?? 0), 0)
  const stockFisicoTotal = (fisicoRes.data ?? []).reduce((a, r) => a + (r.quantity ?? 0), 0)

  // Margen promedio del catálogo (solo productos con costo cargado)
  const conCosto = (prodRes.data ?? []).filter((p) => Number(p.wholesale_price) > 0 && Number(p.price) > 0)
  const margenPct = conCosto.length
    ? Math.round(
        (conCosto.reduce((a, p) => a + (Number(p.price) - Number(p.wholesale_price)) / Number(p.price), 0) /
          conCosto.length) * 100
      )
    : null

  // Proyección próximos 7 días: regresión lineal simple sobre los últimos 7
  const ys = ventas7.map((v) => v.total)
  const n = ys.length
  const xm = (n - 1) / 2
  const ym = ys.reduce((a, b) => a + b, 0) / n
  let num = 0, den = 0
  for (let i = 0; i < n; i++) { num += (i - xm) * (ys[i] - ym); den += (i - xm) ** 2 }
  const b = den ? num / den : 0
  const a = ym - b * xm
  let proyeccion7 = 0
  for (let i = n; i < n + 7; i++) proyeccion7 += Math.max(0, a + b * i)
  proyeccion7 = Math.round(proyeccion7)

  return {
    ventasHoy, pedidosHoy: hoy.length + cajaHoy.length, pedidosMes: mes.length + cajaMes.length, ingresosMes, pagadoMes,
    totalProductos: prodCount.count ?? 0, stockBajo, ultimos, ventas7,
    stockOnlineTotal, stockFisicoTotal, margenPct, proyeccion7
  }
}
