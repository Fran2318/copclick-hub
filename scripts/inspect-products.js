// Uso interno: mira columnas y formatos de products / variants / images en la tienda
import { eco, storeClient } from '../src/supabase.js'

const { data: c } = await eco
  .from('print_clients')
  .select('name,store_supabase_url,store_service_key')
  .limit(1)
  .single()
const db = storeClient(c.store_supabase_url, c.store_service_key)

const { data: p } = await db.from('products').select('*').not('images', 'is', null).limit(2)
console.log('products cols:', p?.[0] ? Object.keys(p[0]).join(', ') : 'sin filas')
console.log('images sample:', JSON.stringify(p?.[0]?.images)?.slice(0, 300))

const { data: v } = await db.from('product_variants').select('*').limit(3)
console.log('product_variants cols:', v?.[0] ? Object.keys(v[0]).join(', ') : 'sin filas')
console.log('variant sample:', JSON.stringify(v?.[0])?.slice(0, 300))

const { data: buckets } = await db.storage.listBuckets()
console.log('storage buckets:', (buckets ?? []).map((b) => `${b.name}(public:${b.public})`).join(', '))
process.exit(0)
