const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { sql } = require('../../lib/db');
const { cors } = require('../../lib/cors');
const { verifyToken } = require('../../lib/auth');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const decoded = verifyToken(req);
    if (!decoded) return res.status(401).json({ error: 'Nao autenticado' });

    const { password, record_id, action, action_detail, meaning } = req.body || {};
    if (!password || !action) return res.status(400).json({ error: 'Senha e acao obrigatorios' });

    const [user] = await sql`
      SELECT id, name, email, pwd_hash FROM users WHERE id = ${decoded.id} AND active = true
    `;
    if (!user) return res.status(401).json({ error: 'Usuario nao encontrado' });

    const valid = await bcrypt.compare(password, user.pwd_hash);
    if (!valid) return res.status(401).json({ error: 'Senha incorreta' });

    const signedAt  = new Date().toISOString();
    const hashInput = `${record_id||''}|${action}|${user.id}|${signedAt}`;
    const hash      = crypto.createHash('sha256').update(hashInput).digest('hex');
    const ip        = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || null;

    const [ins] = await sql`
      INSERT INTO signatures
        (record_id, action, action_detail, signed_by_id, signed_by, signed_at, ip_address, user_agent, meaning, hash)
      VALUES
        (${record_id||null}, ${action}, ${action_detail||null}, ${user.id}, ${user.name},
         ${signedAt}, ${ip}, ${req.headers['user-agent']||null}, ${meaning||action}, ${hash})
      RETURNING id
    `;

    await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${user.name}, 'assinatura', ${action}, ${action_detail||''})`;

    return res.json({
      ok: true,
      signature: {
        signatureId: ins.id, signedById: user.id, signedByName: user.name,
        signedByEmail: user.email, signedAt, hash, action, recordId: record_id
      }
    });
  } catch (err) {
    console.error('Verify-password error:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
};
