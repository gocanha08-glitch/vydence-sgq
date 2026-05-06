const bcrypt = require('bcryptjs');
const { sql } = require('../../lib/db');
const { requireAuth, requireAdmin } = require('../../lib/auth');
const { cors } = require('../../lib/cors');
const { validatePassword } = require('../../lib/passwordPolicy');
const { hasPermission } = require('../../lib/permissions');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { _route, id } = req.query || {};

  // ── GET /api/users/me
  if (req.method === 'GET' && _route === 'me') {
    const decoded = requireAuth(req, res); if (!decoded) return;
    try {
      const [u] = await sql`SELECT id, name, email, area, role, eval_depts, active FROM users WHERE id = ${decoded.id}`;
      const roleRows = await sql`
        SELECT r.id, r.name, r.permissions FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ${decoded.id} ORDER BY r.name
      `;
      const groups      = roleRows.map(r => ({ id: r.id, name: r.name }));
      const permissions = [...new Set(roleRows.flatMap(r => Array.isArray(r.permissions) ? r.permissions : []))];
      return res.json({ ...u, groups, groupIds: groups.map(g => g.id), permissions });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // ── PUT /api/users/:id/roles
  if (req.method === 'PUT' && _route === 'roles' && id) {
    const decoded = requireAdmin(req, res); if (!decoded) return;
    if (!hasPermission(decoded.permissions || [], 'usuarios.gerenciar')) return res.status(403).json({ error: 'Sem permissao' });
    try {
      const { groupIds } = req.body || {};
      await sql`DELETE FROM user_roles WHERE user_id = ${id}`;
      if (Array.isArray(groupIds)) {
        for (const gid of groupIds) {
          await sql`INSERT INTO user_roles (user_id, role_id) VALUES (${id}, ${gid}) ON CONFLICT DO NOTHING`;
        }
      }
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'usuarios', 'Grupos do usuario atualizados', ${'user_id=' + id})`;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // ── PUT /api/users/me (trocar própria senha)
  if (req.method === 'PUT' && _route === 'me') {
    const decoded = requireAuth(req, res); if (!decoded) return;
    try {
      const { _curPwd, _np } = req.body || {};
      if (!_curPwd || !_np) return res.status(400).json({ error: 'Campos obrigatorios' });

      const [u] = await sql`SELECT pwd_hash, name, email FROM users WHERE id = ${decoded.id}`;
      const valid = await bcrypt.compare(_curPwd, u.pwd_hash);
      if (!valid) return res.status(401).json({ error: 'Senha atual incorreta' });

      const policyErr = validatePassword(_np, { name: u.name, email: u.email });
      if (policyErr) return res.status(400).json({ error: policyErr });

      const same = await bcrypt.compare(_np, u.pwd_hash);
      if (same) return res.status(400).json({ error: 'Nova senha nao pode ser igual a atual' });

      const hash = await bcrypt.hash(_np, 10);
      await sql`UPDATE users SET pwd_hash = ${hash}, pwd_hash_prev = ${u.pwd_hash} WHERE id = ${decoded.id}`;
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'sistema', 'Senha alterada pelo proprio usuario', ${decoded.email})`;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // ── GET /api/users — listar todos
  if (req.method === 'GET') {
    const decoded = requireAuth(req, res); if (!decoded) return;
    try {
      const rows = await sql`SELECT id, name, email, area, role, eval_depts, active, created_at FROM users ORDER BY name`;
      const urRows = await sql`
        SELECT ur.user_id, r.id, r.name, r.permissions
        FROM user_roles ur JOIN roles r ON r.id = ur.role_id ORDER BY r.name
      `;
      const groupsByUser = {}; const permsByUser = {};
      for (const ur of urRows) {
        if (!groupsByUser[ur.user_id]) groupsByUser[ur.user_id] = [];
        if (!permsByUser[ur.user_id])  permsByUser[ur.user_id]  = new Set();
        groupsByUser[ur.user_id].push({ id: ur.id, name: ur.name });
        (Array.isArray(ur.permissions) ? ur.permissions : []).forEach(p => permsByUser[ur.user_id].add(p));
      }
      return res.json(rows.map(u => ({
        id: u.id, name: u.name, email: u.email, area: u.area,
        role: u.role, evalDepts: u.eval_depts || [], active: u.active, createdAt: u.created_at,
        groups:      groupsByUser[u.id] || [],
        groupIds:    (groupsByUser[u.id] || []).map(g => g.id),
        permissions: [...(permsByUser[u.id] || [])]
      })));
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // ── POST /api/users — criar
  if (req.method === 'POST') {
    const decoded = requireAdmin(req, res); if (!decoded) return;
    if (!hasPermission(decoded.permissions || [], 'usuarios.gerenciar')) return res.status(403).json({ error: 'Sem permissao' });
    try {
      const { name, email, pwd, area, role, groupIds, evalDepts } = req.body || {};
      if (!name || !email || !pwd) return res.status(400).json({ error: 'Nome, email e senha obrigatorios' });

      const policyErr = validatePassword(pwd, { name, email });
      if (policyErr) return res.status(400).json({ error: policyErr });

      const hash = await bcrypt.hash(pwd, 10);
      const [created] = await sql`
        INSERT INTO users (name, email, area, role, pwd_hash, eval_depts, active, created_by)
        VALUES (${name}, ${email.toLowerCase().trim()}, ${area||''}, ${role||'geral'},
                ${hash}, ${JSON.stringify(evalDepts||[])}::jsonb, true, ${decoded.name})
        RETURNING id, name, email, area, role, eval_depts, active
      `;
      if (Array.isArray(groupIds)) {
        for (const gid of groupIds) {
          await sql`INSERT INTO user_roles (user_id, role_id) VALUES (${created.id}, ${gid}) ON CONFLICT DO NOTHING`;
        }
      }
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'usuarios', 'Usuario criado', ${name + ' (' + email + ')'})`;
      return res.status(201).json({ ok: true, user: created });
    } catch (err) {
      if (err.message?.includes('unique')) return res.status(409).json({ error: 'Email ja cadastrado' });
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  // ── PUT /api/users — editar
  if (req.method === 'PUT') {
    const decoded = requireAdmin(req, res); if (!decoded) return;
    if (!hasPermission(decoded.permissions || [], 'usuarios.gerenciar')) return res.status(403).json({ error: 'Sem permissao' });
    try {
      const { id: uid, name, email, pwd, area, role, groupIds, evalDepts, active } = req.body || {};
      if (!uid) return res.status(400).json({ error: 'ID obrigatorio' });

      if (pwd) {
        const policyErr = validatePassword(pwd, { name, email });
        if (policyErr) return res.status(400).json({ error: policyErr });
        const [u] = await sql`SELECT pwd_hash FROM users WHERE id = ${uid}`;
        const same = await bcrypt.compare(pwd, u.pwd_hash);
        if (same) return res.status(400).json({ error: 'Nova senha nao pode ser igual a atual' });
        const hash = await bcrypt.hash(pwd, 10);
        await sql`UPDATE users SET name=${name}, email=${email.toLowerCase()}, area=${area||''},
          role=${role||'geral'}, eval_depts=${JSON.stringify(evalDepts||[])}::jsonb, active=${active!==false},
          pwd_hash=${hash}, pwd_hash_prev=${u.pwd_hash} WHERE id=${uid}`;
      } else {
        await sql`UPDATE users SET name=${name}, email=${email.toLowerCase()}, area=${area||''},
          role=${role||'geral'}, eval_depts=${JSON.stringify(evalDepts||[])}::jsonb, active=${active!==false} WHERE id=${uid}`;
      }

      if (Array.isArray(groupIds)) {
        await sql`DELETE FROM user_roles WHERE user_id = ${uid}`;
        for (const gid of groupIds) {
          await sql`INSERT INTO user_roles (user_id, role_id) VALUES (${uid}, ${gid}) ON CONFLICT DO NOTHING`;
        }
      }
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'usuarios', 'Usuario editado', ${name + ' (id=' + uid + ')'})`;
      return res.json({ ok: true });
    } catch (err) {
      if (err.message?.includes('unique')) return res.status(409).json({ error: 'Email ja cadastrado' });
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
