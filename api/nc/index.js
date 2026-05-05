const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { hasPermission } = require('../../lib/permissions');
const { nextSequence } = require('../../lib/sequences');
const { saveSignature } = require('../../lib/signatures');
const cors = require('../../lib/cors');
module.exports = async (req, res) => {
  cors(req, res); if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res); if (!user) return;
  if (req.method === 'GET') {
    try {
      const { status, limit=100, offset=0 } = req.query;
      const rows = status
        ? await sql`SELECT id, status, data, created_at, updated_at FROM records WHERE module='nc' AND status=${status} ORDER BY created_at DESC LIMIT ${parseInt(limit)} OFFSET ${parseInt(offset)}`
        : await sql`SELECT id, status, data, created_at, updated_at FROM records WHERE module='nc' ORDER BY created_at DESC LIMIT ${parseInt(limit)} OFFSET ${parseInt(offset)}`;
      return res.json(rows);
    } catch(err) { return res.status(500).json({ error: 'Erro ao buscar NCs' }); }
  }
  if (req.method === 'POST') {
    if (!hasPermission(user.permissions, 'nc.abrir')) return res.status(403).json({ error: 'Sem permissao para abrir NC' });
    try {
      const body = req.body || {};
      const id = await nextSequence('nc');
      const data = { ...body, id, status:'aberto', createdBy:user.id, createdByName:user.name, createdAt:new Date().toISOString(), acoes:[], log:[{at:new Date().toISOString(),by:user.name,event:'NC aberta',detail:''}] };
      await sql`INSERT INTO records (id, module, status, data, created_by) VALUES (${id}, 'nc', 'aberto', ${JSON.stringify(data)}, ${user.id})`;
      await saveSignature(req, { recordId:id, module:'nc', userId:user.id, userName:user.name, action:'abertura', detail:'NC aberta', meaning:'Confirmo a abertura desta NC' });
      return res.status(201).json({ id, ok:true });
    } catch(err) { return res.status(500).json({ error: 'Erro ao criar NC', detail: err.message }); }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};