const bcrypt = require('bcryptjs');
const { sql } = require('../../lib/db');
const { signToken } = require('../../lib/auth');
const { cors } = require('../../lib/cors');

const rateLimitMap = new Map();
function checkRateLimit(req, res) {
  const ip  = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  const now = Date.now();
  const e   = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - e.start > 60000) { rateLimitMap.set(ip, { count: 1, start: now }); return false; }
  if (e.count >= 10) {
    res.setHeader('Retry-After', '60');
    res.status(429).json({ error: 'Muitas tentativas. Aguarde 1 minuto.' });
    return true;
  }
  e.count++; rateLimitMap.set(ip, e); return false;
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (checkRateLimit(req, res)) return;

  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatorios' });

    const rows = await sql`
      SELECT id, name, email, area, role, pwd_hash, eval_depts, active, locked_until, login_attempts
      FROM users WHERE email = ${email.toLowerCase().trim()} LIMIT 1
    `;
    const user = rows[0];
    if (!user || !user.active) return res.status(401).json({ error: 'Usuario nao encontrado ou inativo' });

    // Verificar bloqueio
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(401).json({ error: 'Conta bloqueada temporariamente. Tente novamente mais tarde.' });
    }

    const valid = await bcrypt.compare(password, user.pwd_hash);
    if (!valid) {
      const attempts = (user.login_attempts || 0) + 1;
      if (attempts >= 5) {
        const lockUntil = new Date(Date.now() + 15 * 60000).toISOString();
        await sql`UPDATE users SET login_attempts = ${attempts}, locked_until = ${lockUntil} WHERE id = ${user.id}`;
        return res.status(401).json({ error: 'Conta bloqueada por 15 minutos apos multiplas tentativas.' });
      }
      await sql`UPDATE users SET login_attempts = ${attempts} WHERE id = ${user.id}`;
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    // Reset contadores
    await sql`UPDATE users SET login_attempts = 0, locked_until = null WHERE id = ${user.id}`;

    // Buscar grupos e permissões
    const roleRows = await sql`
      SELECT r.id, r.name, r.permissions
      FROM roles r JOIN user_roles ur ON ur.role_id = r.id
      WHERE ur.user_id = ${user.id} ORDER BY r.name
    `;
    const groups      = roleRows.map(r => ({ id: r.id, name: r.name }));
    const groupIds    = roleRows.map(r => r.id);
    const allPerms    = roleRows.flatMap(r => Array.isArray(r.permissions) ? r.permissions : []);
    const permissions = [...new Set(allPerms)];

    const userData = {
      id: user.id, name: user.name, email: user.email, area: user.area,
      role: user.role, evalDepts: user.eval_depts || [],
      permissions, groups, groupIds
    };
    const token = signToken(userData);

    // Auditoria
    await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${user.name}, 'sistema', 'Login realizado', ${user.email})`;

    return res.json({ token, user: userData });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
};
