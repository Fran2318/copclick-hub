import { createClient } from '@supabase/supabase-js'
import WebSocket from 'ws'
import { CONFIG } from './config.js'

// En Node (Railway) no hay WebSocket global < Node 22 → le pasamos el de 'ws'.
const realtime = { transport: WebSocket }

// Cliente del ecosistema (service_role → bypassa RLS; solo server-side).
export const eco = createClient(CONFIG.ecosystemUrl, CONFIG.ecosystemServiceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
  realtime
})

// Cliente para el Supabase de una tienda (para la ingesta por Realtime).
export function storeClient(url, serviceKey) {
  return createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    realtime
  })
}
