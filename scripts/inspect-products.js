// Uso interno: mira qué columnas tiene products / product_images en la tienda
import { eco, storeClient } from '../src/supabase.js'

const { data: c } = await eco
  .from('print_clients')
  .select('name,store_supabase_url,store_service_key')
  .limit(1)
  .single()
const db = storeClient(c.store_supabase_url, c.store_service_key)

const { data: p } = await db.from('products').select('*').limit(1)
console.log('products cols:', p?.[0] ? Object.keys(p[0]).join(', ') : 'sin filas')

const { data: img, error } = await db.from('product_images').select('*').limit(1)
console.log('product_images:', error ? 'ERROR ' + error.message : img?.[0] ? Object.keys(img[0]).join(', ') : 'sin filas')
process.exit(0)
