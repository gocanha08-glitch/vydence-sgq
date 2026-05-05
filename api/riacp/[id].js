const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { hasPermission } = require('../../lib/permissions');
const { saveSignature } = require('../../lib/signatures');
const cors = require('../../lib/cors');
const RIACP_STATUS = ['aberto','investigacao','plano_de_acao','avaliacao_eficacia','concluido','cancelado'];
const LABELS = {
  investigacao:       {action:'investigacao',      detail:'RIACP em Investigacao',         meaning:'Confirmo inicio da investigacao'},
  plano_de_acao:      {action:'plano_de_acao',     detail:'Plano de Acao definido',         meaning:'Confirmo investigacao e aprovo plano'},
  avaliacao_eficacia: {action:'avaliacao_eficacia',detail:'Avaliacao de Eficacia iniciada', meaning:'Confirmo execucao das acoes'},
  concluido:          {action:'conclusao',         detail:'RIACP Concluida',                meaning:'Confirmo eficacia e encerramento'},
  cancelado:          {action:'cancelamento',      detail:'RIACP Cancelada',                meaning:'Confirmo cancelamento'},
};
module.exports = async (req, res) => {
  cors(req, res); if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res); if (!user) return;
  const { id } = req.query; if (!id) return res.status(400).json({ error: 'ID obrigatorio' });
  if (req.method === 'GET') {
    try {
      const rows = await sql`SELECT data FROM records WHERE id=${id} AND module='riacp' LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ error: 'RIACP nao encontrada' });
      const links = await sql`SELECT from_id, from_module, link_type FROM record_links WHERE to_id=${id}`;
      const data = rows[0].data; data.links = links;
      return res.json(data);
    } catch { return res.status(500).json({ error: 'Erro ao buscar RIACP' }); }
  }
  if (req.method === 'PUT') {
    try {
      const newData = req.body; if (!newData) return res.status(400).json({ error: 'Dados invalidos' });
      const rows = await sql`SELECT data FROM records WHERE id=${id} AND module='riacp' LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ error: 'RIACP nao encontrada' });
      const currentData = rows[0].data;
      const oldStatus = currentData.status||'aberto'; const newStatus = newData.status||oldStatus;
      if (!RIACP_STATUS.includes(newStatus)) return res.status(400).json({ error: 'Status invalido' });
      if ((oldStatus==='concluido'||oldStatus==='cancelado') && newStatus!==oldStatus) return res.status(403).json({ error: 'RIACP encerrada' });
      if (newStatus==='cancelado' && !hasPermission(user.permissions,'riacp.cancelar')) return res.status(403).json({ error: 'Sem permissao para cancelar' });
      if (newStatus==='concluido' && !hasPermission(user.permissions,'riacp.concluir')) return res.status(403).json({ error: 'Sem permissao para concluir' });
      const log = [...(newData.log||currentData.log||[])];
      if (oldStatus!==newStatus) log.push({ at:new Date().toISOString(), by:user.name, event:oldStatus+' -> '+newStatus, detail:newData.logNote||'' });
      newData.log = log; newData.updatedAt = new Date().toISOString();
      await sql`UPDATE records SET data=${JSON.stringify(newData)}, status=${newStatus}, updated_at=now() WHERE id=${id}`;
      if (oldStatus!==newStatus) { const lbl=LABELS[newStatus]||{action:newStatus,detail:'Status: '+newStatus,meaning:'Confirmo'}; await saveSignature(req,{recordId:id,module:'riacp',userId:user.id,userName:user.name,...lbl}); }
      return res.json({ ok:true });
    } catch(err) { return res.status(500).json({ error: 'Erro ao atualizar RIACP', detail: err.message }); }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};