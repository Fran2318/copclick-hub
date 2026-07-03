import fs from 'fs'

// Carga .env local si existe (Railway inyecta las variables directamente).
try {
  const raw = fs.readFileSync(new URL('../.env', import.meta.url), 'utf8')
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^\s*([\w.]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '')
  }
} catch {
  /* sin .env: usamos las variables del entorno */
}

export const CONFIG = {
  port: Number(process.env.PORT || 8080),
  ecosystemUrl: process.env.ECOSYSTEM_SUPABASE_URL,
  ecosystemServiceKey: process.env.ECOSYSTEM_SERVICE_KEY,
  adminKey: process.env.ADMIN_KEY || ''
}

if (!CONFIG.ecosystemUrl || !CONFIG.ecosystemServiceKey) {
  console.error('[config] Faltan ECOSYSTEM_SUPABASE_URL / ECOSYSTEM_SERVICE_KEY')
  process.exit(1)
}
