// Crea un cliente del ecosistema: genera un token fuerte, guarda solo su hash,
// y muestra el token UNA sola vez. Correr localmente:  npm run create-client
import crypto from 'crypto'
import readline from 'readline'
import { eco } from './supabase.js'

function ask(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  return new Promise((r) => rl.question(q, (a) => (rl.close(), r(a.trim()))))
}

const name = await ask('Nombre del cliente (ej. Paradise): ')
const store_name = (await ask('store_name para el ticket [' + name + ']: ')) || name
const store_web = await ask('store_web (ej. paradisemoda.com): ')
const store_supabase_url = await ask('URL del Supabase de la tienda: ')
const store_service_key = await ask('service_role key de la tienda (secreta): ')

const token = crypto.randomBytes(24).toString('hex')
const token_hash = crypto.createHash('sha256').update(token).digest('hex')

const { data, error } = await eco
  .from('print_clients')
  .insert({ name, token_hash, store_name, store_web, store_supabase_url, store_service_key, status: 'active' })
  .select('id')
  .single()

if (error) {
  console.error('\n❌ Error:', error.message)
  process.exit(1)
}

console.log('\n✅ Cliente creado. id =', data.id)
console.log('\n🔑 TOKEN (copialo AHORA, no se vuelve a mostrar):\n')
console.log('    ' + token + '\n')
console.log('En el config.json del .exe del cliente:')
console.log('  "token": "' + token + '"')
console.log('  "serverUrl": "wss://<tu-hub>.up.railway.app"   (sin /ws/print)')
process.exit(0)
