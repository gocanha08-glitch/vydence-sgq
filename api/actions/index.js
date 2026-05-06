const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { cors } = require('../../lib/cors');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = requireAuth(req, res); if (!decoded) return;
  const { record_id, id } = req.query || {};

  if (!record_id) return res.status(400).json({ error: 'record_id obrigatorio' });

  if (req.method === 'GET') {
    try {
      const rows = await sql`SELECT * FROM actions WHERE record_id = ${record_id} ORDER BY created_at`;
      return res.json(rows);
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  if (req.method === 'POST') {
    try {
      const { description, responsible, due_date } = req.body || {};
      if (!description?.trim()) return res.status(400).json({ error: 'Descricao obrigatoria' });
      const [action] = await sql`
        INSERT INTO actions (record_id, description, responsible, due_date, created_by)
        VALUES (${record_id}, ${description.trim()}, ${responsible||''}, ${due_date||null}, ${decoded.name})
        RETURNING *
      `;
      return res.status(201).json(action);
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  if (req.method === 'PUT' && id) {
    try {
      const { description, responsible, due_date, done } = req.body || {};
      await sql`
        UPDATE actions SET
          description = ${description},
          responsible = ${responsible||''},
          due_date    = ${due_date||null},
          done        = ${done===true},
          done_at     = ${done===true ? new Date().toISOString() : null}
        WHERE id = ${id} AND record_id = ${record_id}
      `;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  if (req.method === 'DELETE' && id) {
    try {
      await sql`DELETE FROM actions WHERE id = ${id} AND record_id = ${record_id}`;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
