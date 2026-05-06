const { sql } = require('../../lib/db');
const { requireAuth, requireAdmin } = require('../../lib/auth');
const { cors } = require('../../lib/cors');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const key = req.query.key;
  if (!key) return res.status(400).json({ error: 'Chave obrigatoria' });

  // GET — ler config
  if (req.method === 'GET') {
    const decoded = requireAuth(req, res); if (!decoded) return;
    try {
      // syslog: retorna últimas 200 entradas
      if (key === 'syslog') {
        const rows = await sql`SELECT id, at, by, type, event, detail FROM syslog ORDER BY at DESC LIMIT 200`;
        return res.json(rows);
      }
      const rows = await sql`SELECT value FROM config WHERE key = ${key} LIMIT 1`;
      return res.json(rows[0] ? rows[0].value : null);
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // PUT — salvar config
  if (req.method === 'PUT') {
    const decoded = requireAuth(req, res); if (!decoded) return;
    try {
      const { value } = req.body || {};
      if (key === 'syslog') {
        const entries = Array.isArray(value) ? value : [value];
        for (const e of entries) {
          await sql`
            INSERT INTO syslog (at, by, type, event, detail)
            VALUES (${e.at || new Date().toISOString()}, ${e.by||''}, ${e.type||'sistema'}, ${e.event||''}, ${e.detail||''})
          `;
        }
        return res.json({ ok: true });
      }
      const decoded2 = requireAdmin(req, res); if (!decoded2) return;
      await sql`
        INSERT INTO config (key, value, updated_at, updated_by)
        VALUES (${key}, ${JSON.stringify(value)}::jsonb, now(), ${decoded.name})
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by
      `;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
