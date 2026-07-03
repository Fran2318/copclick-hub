import { createClient } from '@supabase/supabase-js'
import { CONFIG } from './config.js'

// Cliente del ecosistema (service_role → bypassa RLS; solo server-side).
export const eco = createClient(CONFIG.ecosystemUrl, CONFIG.ecosystemServiceKey, {
  auth: { persistSession: false, autoRefreshToken: false }
})

// Cliente para el Supabase de una tienda (para la ingesta por Realtime).
export function storeClient(url, serviceKey) {
  return createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false }
  })
}
