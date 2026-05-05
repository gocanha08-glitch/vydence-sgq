const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const cors = require('../../lib/cors');
module.exports = async (req, res) => {
  cors(req, res, 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res);
  if (!user) return;
  if (req.method === 'GET') {
    try {
      const { module, record_id } = req.query;
      let rows;
      if (record_id) rows = await sql`SELECT * FROM signatures WHERE record_id=${record_id} ORDER BY signed_at DESC`;
      else if (module) rows = await sql`SELECT * FROM signatures WHERE module=${module} ORDER BY signed_at DESC LIMIT 200`;
      else rows = await sql`SELECT * FROM signatures ORDER BY signed_at DESC LIMIT 200`;
      return res.json(rows);
    } catch(err) { return res.status(500).json({ error: 'Erro ao buscar assinaturas' }); }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};