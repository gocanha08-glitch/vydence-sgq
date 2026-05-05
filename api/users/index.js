const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { hasPermission } = require('../../lib/permissions');
const cors = require('../../lib/cors');
const bcrypt = require('bcryptjs');
module.exports = async (req, res) => {
  cors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res);
  if (!user) return;
  if (req.method === 'GET') {
    try {
      const rows = await sql`
        SELECT u.id, u.name, u.email, u.active, u.is_admin, u.created_at,
               COALESCE(json_agg(json_build_object('id', g.id, 'name', g.name)) FILTER (WHERE g.id IS NOT NULL), '[]') AS groups
        FROM users u LEFT JOIN user_groups ug ON ug.user_id = u.id LEFT JOIN groups g ON g.id = ug.group_id
        GROUP BY u.id ORDER BY u.name
      `;
      return res.json(rows);
    } catch(err) { return res.status(500).json({ error: 'Erro ao buscar usuarios' }); }
  }
  if (req.method === 'POST') {
    if (!hasPermission(user.permissions, 'admin.usuarios') && !user.isAdmin) return res.status(403).json({ error: 'Sem permissao' });
    const { name, email, password, groupIds = [] } = req.body || {};
    if (!name||!email||!password) return res.status(400).json({ error: 'Nome, email e senha obrigatorios' });
    try {
      const hash = await bcrypt.hash(password, 10);
      const newUser = await sql`INSERT INTO users (name, email, password) VALUES (${name}, ${email.toLowerCase()}, ${hash}) RETURNING id`;
      const uid = newUser[0].id;
      for (const gid of groupIds) await sql`INSERT INTO user_groups (user_id, group_id) VALUES (${uid}, ${gid}) ON CONFLICT DO NOTHING`;
      return res.status(201).json({ id: uid, ok: true });
    } catch(err) {
      if (err.message.includes('unique')) return res.status(400).json({ error: 'Email ja cadastrado' });
      return res.status(500).json({ error: 'Erro ao criar usuario' });
    }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};