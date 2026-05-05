const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { hasPermission } = require('../../lib/permissions');
const cors = require('../../lib/cors');
module.exports = async (req, res) => {
  cors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res);
  if (!user) return;
  if (req.method === 'GET') {
    try {
      const rows = await sql`SELECT id, name, description, permissions, created_at FROM groups ORDER BY name`;
      return res.json(rows);
    } catch(err) { return res.status(500).json({ error: 'Erro ao buscar grupos' }); }
  }
  if (req.method === 'POST') {
    if (!hasPermission(user.permissions, 'admin.grupos') && !user.isAdmin) return res.status(403).json({ error: 'Sem permissao' });
    const { name, description, permissions = [] } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Nome obrigatorio' });
    try {
      const row = await sql`INSERT INTO groups (name, description, permissions) VALUES (${name}, ${description||''}, ${JSON.stringify(permissions)}) RETURNING id`;
      return res.status(201).json({ id: row[0].id, ok: true });
    } catch(err) { return res.status(500).json({ error: 'Erro ao criar grupo' }); }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};