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
const PROD_FIELDS = ['name', 'description', 'price', 'stock', 'category', 'code', 'is_active', 'wholesale_price']

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

// ---------- Stock físico por sucursal ----------
export async function getBranchStock(session) {
  const { data } = await eco
    .from('store_branch_stock')
    .select('branch_id,product_id,quantity')
    .eq('client_id', session.client_id)
  return data ?? []
}

export async function adjustBranchStock(session, body) {
  const { branch_id, product_id, delta, nombre } = body
  if (!branch_id || !product_id) return { error: 'faltan datos' }
  const { data: cur } = await eco
    .from('store_branch_stock')
    .select('id,quantity')
    .eq('branch_id', branch_id)
    .eq('product_id', product_id)
    .maybeSingle()
  const prev = cur?.quantity ?? 0
  const nuevo = Math.max(0, prev + Number(delta || 0))
  const { error } = await eco.from('store_branch_stock').upsert(
    {
      client_id: session.client_id,
      branch_id,
      product_id,
      quantity: nuevo,
      updated_at: new Date().toISOString(),
      updated_by: session.name
    },
    { onConflict: 'branch_id,product_id' }
  )
  if (error) return { error: error.message }
  logActivity(session, 'stock_fisico', `${nombre || product_id}: ${prev} → ${nuevo}`)
  return { ok: true, quantity: nuevo }
}

// ---------- Transferencias entre sucursales ----------
export async function listTransfers(session) {
  const { data } = await eco
    .from('store_transfers')
    .select('id,product_name,from_branch_id,to_branch_id,quantity,transferred_by,transferred_at')
    .eq('client_id', session.client_id)
    .order('transferred_at', { ascending: false })
    .limit(30)
  return data ?? []
}

export async function transferStock(session, body) {
  const { product_id, nombre, from_branch_id, to_branch_id, quantity } = body
  const qty = Number(quantity || 0)
  if (!product_id || !from_branch_id || !to_branch_id || qty <= 0) return { error: 'datos incompletos' }
  if (from_branch_id === to_branch_id) return { error: 'origen y destino son la misma sucursal' }

  const { data: origen } = await eco
    .from('store_branch_stock')
    .select('quantity')
    .eq('branch_id', from_branch_id)
    .eq('product_id', product_id)
    .maybeSingle()
  const disp = origen?.quantity ?? 0
  if (qty > disp) return { error: `stock insuficiente en origen (hay ${disp})` }

  const r1 = await adjustBranchStock(session, { branch_id: from_branch_id, product_id, delta: -qty, nombre })
  if (r1.error) return r1
  const r2 = await adjustBranchStock(session, { branch_id: to_branch_id, product_id, delta: qty, nombre })
  if (r2.error) return r2

  await eco.from('store_transfers').insert({
    client_id: session.client_id,
    product_id,
    product_name: nombre || null,
    from_branch_id,
    to_branch_id,
    quantity: qty,
    transferred_by: session.name
  })
  logActivity(session, 'transferencia', `${nombre || product_id} ×${qty}`)
  return { ok: true }
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

  // Buckets mensuales: ingresos, COGS (costo de lo vendido), cobertura de costos
  const meses = new Map() // 'YYYY-MM' -> { ingresos, cogs }
  let qtyTotal = 0, qtyConCosto = 0
  for (const o of orders ?? []) {
    const m = laPazMonth(o.created_at)
    if (!meses.has(m)) meses.set(m, { ingresos: 0, cogs: 0 })
    meses.get(m).ingresos += Number(o.total || 0)
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

  const nPedidos = (orders ?? []).length
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
    .select('id,name,code,price,stock,category,description,is_active,wholesale_price')
    .order('name')
  return (data ?? []).map((p) => ({
    id: p.id,
    nombre: p.name,
    sku: p.code,
    precio: Number(p.price || 0),
    costo: Number(p.wholesale_price || 0),
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

  const [prodRes, recentRes, weekRes, monthRes, prodCount, fisicoRes] = await Promise.all([
    db.from('products').select('name,stock,price,wholesale_price'),
    db.from('orders').select('order_number,customer_name,total,status,created_at').order('created_at', { ascending: false }).limit(6),
    db.from('orders').select('total,created_at').gte('created_at', sevenAgo.toISOString()),
    db.from('orders').select('total,payment_status,created_at').gte('created_at', monthStart),
    db.from('products').select('id', { count: 'exact', head: true }),
    eco.from('store_branch_stock').select('quantity').eq('client_id', session.client_id)
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
    ventasHoy, pedidosHoy: hoy.length, pedidosMes: mes.length, ingresosMes, pagadoMes,
    totalProductos: prodCount.count ?? 0, stockBajo, ultimos, ventas7,
    stockOnlineTotal, stockFisicoTotal, margenPct, proyeccion7
  }
}
