const { sql } = require('../../lib/db');
const { signToken } = require('../../lib/auth');
const cors = require('../../lib/cors');
const bcrypt = require('bcryptjs');
module.exports = async (req, res) => {
  cors(req, res, 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatorios' });
  try {
    const users = await sql`
      SELECT u.id, u.name, u.email, u.password, u.is_admin, u.active,
             COALESCE(array_agg(DISTINCT perm) FILTER (WHERE perm IS NOT NULL), '{}') AS permissions
      FROM users u
      LEFT JOIN user_groups ug ON ug.user_id = u.id
      LEFT JOIN groups g ON g.id = ug.group_id
      LEFT JOIN LATERAL jsonb_array_elements_text(g.permissions) AS perm ON true
      WHERE u.email = ${email.toLowerCase()}
      GROUP BY u.id
    `;
    const user = users[0];
    if (!user || !user.active) return res.status(401).json({ error: 'Usuario nao encontrado' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Senha incorreta' });
    const token = signToken(user);
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email, isAdmin: user.is_admin, permissions: user.permissions } });
  } catch(err) {
    console.error('[login]', err.message);
    return res.status(500).json({ error: 'Erro interno' });
  }
};