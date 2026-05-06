const { sql } = require('../../lib/db');
const { requireAdmin } = require('../../lib/auth');
const { cors } = require('../../lib/cors');
const { ALL_PERMISSIONS, hasPermission } = require('../../lib/permissions');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = requireAdmin(req, res); if (!decoded) return;

  // GET — listar grupos com contagem de usuários
  if (req.method === 'GET') {
    try {
      const rows = await sql`
        SELECT r.id, r.name, r.description, r.permissions, r.is_system, r.created_at,
               COUNT(ur.user_id)::int as user_count
        FROM roles r LEFT JOIN user_roles ur ON ur.role_id = r.id
        GROUP BY r.id ORDER BY r.is_system DESC, r.name
      `;
      return res.json(rows);
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  if (!hasPermission(decoded.permissions || [], 'grupos.gerenciar')) return res.status(403).json({ error: 'Sem permissao' });

  // POST — criar
  if (req.method === 'POST') {
    try {
      const { name, description, permissions } = req.body || {};
      if (!name?.trim()) return res.status(400).json({ error: 'Nome obrigatorio' });
      const validPerms = (permissions || []).filter(p => ALL_PERMISSIONS.includes(p));
      const [created] = await sql`
        INSERT INTO roles (name, description, permissions, is_system, created_by)
        VALUES (${name.trim()}, ${description?.trim()||null}, ${JSON.stringify(validPerms)}::jsonb, false, ${decoded.name})
        RETURNING id, name, description, permissions, is_system, created_at
      `;
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'grupos', 'Grupo criado', ${name})`;
      return res.status(201).json(created);
    } catch (err) {
      if (err.message?.includes('unique')) return res.status(409).json({ error: 'Nome ja existe' });
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  // PUT — editar
  if (req.method === 'PUT') {
    try {
      const { id, name, description, permissions } = req.body || {};
      if (!id) return res.status(400).json({ error: 'ID obrigatorio' });
      const [existing] = await sql`SELECT is_system FROM roles WHERE id = ${id}`;
      if (!existing) return res.status(404).json({ error: 'Grupo nao encontrado' });
      const validPerms = (permissions || []).filter(p => ALL_PERMISSIONS.includes(p));
      if (existing.is_system) {
        await sql`UPDATE roles SET description=${description?.trim()||null}, permissions=${JSON.stringify(validPerms)}::jsonb WHERE id=${id}`;
      } else {
        if (!name?.trim()) return res.status(400).json({ error: 'Nome obrigatorio' });
        await sql`UPDATE roles SET name=${name.trim()}, description=${description?.trim()||null}, permissions=${JSON.stringify(validPerms)}::jsonb WHERE id=${id}`;
      }
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'grupos', 'Grupo editado', ${'id=' + id})`;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // DELETE — excluir
  if (req.method === 'DELETE') {
    try {
      const { id } = req.body || req.query || {};
      if (!id) return res.status(400).json({ error: 'ID obrigatorio' });
      const [existing] = await sql`SELECT is_system, name FROM roles WHERE id = ${id}`;
      if (!existing) return res.status(404).json({ error: 'Grupo nao encontrado' });
      if (existing.is_system) return res.status(400).json({ error: 'Grupos do sistema nao podem ser excluidos' });
      const [{ count }] = await sql`SELECT COUNT(*)::int as count FROM user_roles WHERE role_id = ${id}`;
      if (count > 0) return res.status(400).json({ error: `Grupo possui ${count} usuario(s). Remova-os antes de excluir.` });
      await sql`DELETE FROM roles WHERE id = ${id}`;
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, 'grupos', 'Grupo excluido', ${existing.name})`;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
