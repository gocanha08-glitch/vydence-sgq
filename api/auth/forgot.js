const crypto = require('crypto');
const { sql } = require('../../lib/db');
const { cors } = require('../../lib/cors');
const { sendResetPassword } = require('../../lib/email/mailer');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email obrigatorio' });

    const rows = await sql`
      SELECT id, name FROM users WHERE email = ${email.toLowerCase().trim()} AND active = true LIMIT 1
    `;
    // Sempre retorna ok para não revelar se email existe
    if (!rows.length) return res.json({ ok: true });

    const user    = rows[0];
    const token   = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000).toISOString();

    await sql`UPDATE users SET reset_token = ${token}, reset_expires = ${expires} WHERE id = ${user.id}`;

    await sendResetPassword({
      to: email,
      name: user.name,
      resetUrl: `${process.env.APP_URL}/reset?token=${token}`
    });

    await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${user.name}, 'sistema', 'Solicitacao reset senha', ${email})`;

    return res.json({ ok: true });
  } catch (err) {
    console.error('Forgot error:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
};
