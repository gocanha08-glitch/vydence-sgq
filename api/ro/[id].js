const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { hasPermission } = require('../../lib/permissions');
const { saveSignature } = require('../../lib/signatures');
const { nextSequence } = require('../../lib/sequences');
const cors = require('../../lib/cors');
const RO_STATUS = ['aberto','em_analise','concluido','cancelado'];
const LABELS = { em_analise:{action:'em_analise',detail:'RO em Analise',meaning:'Confirmo inicio da analise'}, concluido:{action:'conclusao',detail:'RO Concluida',meaning:'Confirmo a conclusao desta RO'}, cancelado:{action:'cancelamento',detail:'RO Cancelada',meaning:'Confirmo o cancelamento'} };
module.exports = async (req, res) => {
  cors(req, res); if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res); if (!user) return;
  const { id } = req.query; if (!id) return res.status(400).json({ error: 'ID obrigatorio' });
  if (req.method === 'GET') {
    try {
      const rows = await sql`SELECT data FROM records WHERE id=${id} AND module='ro' LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ error: 'RO nao encontrada' });
      return res.json(rows[0].data);
    } catch(err) { return res.status(500).json({ error: 'Erro ao buscar RO' }); }
  }
  if (req.method === 'PUT') {
    try {
      const newData = req.body; if (!newData) return res.status(400).json({ error: 'Dados invalidos' });
      const rows = await sql`SELECT data FROM records WHERE id=${id} AND module='ro' LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ error: 'RO nao encontrada' });
      const currentData = rows[0].data;
      const oldStatus = currentData.status || 'aberto';
      const newStatus = newData.status || oldStatus;
      if (!RO_STATUS.includes(newStatus)) return res.status(400).json({ error: 'Status invalido' });
      if ((oldStatus==='concluido'||oldStatus==='cancelado') && newStatus!==oldStatus) return res.status(403).json({ error: 'RO encerrada nao pode ser alterada' });
      if (newStatus==='cancelado' && !hasPermission(user.permissions,'ro.cancelar')) return res.status(403).json({ error: 'Sem permissao para cancelar' });
      const log = [...(newData.log||currentData.log||[])];
      if (oldStatus!==newStatus) log.push({ at: new Date().toISOString(), by: user.name, event: oldStatus+' -> '+newStatus, detail: newData.logNote||'' });
      newData.log = log; newData.updatedAt = new Date().toISOString();
      await sql`UPDATE records SET data=${JSON.stringify(newData)}, status=${newStatus}, updated_at=now() WHERE id=${id}`;
      if (oldStatus!==newStatus) { const lbl = LABELS[newStatus]||{action:newStatus,detail:'Status: '+newStatus,meaning:'Confirmo'}; await saveSignature(req, { recordId:id, module:'ro', userId:user.id, userName:user.name, ...lbl }); }
      if (newData.decisaoFinal==='abrir_nc' && newData.abrirNC && !currentData.ncId) {
        try {
          const ncId = await nextSequence('nc');
          const ncData = { id:ncId, status:'aberto', localAbertura:newData.local||'', tipoNC:newData.tipoRO||'Produto', codigo:newData.codigo||'', descricaoPeca:newData.descricaoPeca||'', quantidade:newData.quantidade||'', lote:newData.lote||'', descricaoNC:newData.descricaoOcorrencia||'', equipamento:newData.equipamento||'', origemRO:id, createdBy:user.id, createdByName:user.name, createdAt:new Date().toISOString(), log:[{at:new Date().toISOString(),by:user.name,event:'NC aberta a partir de '+id,detail:''}] };
          await sql`INSERT INTO records (id, module, status, data, created_by) VALUES (${ncId}, 'nc', 'aberto', ${JSON.stringify(ncData)}, ${user.id})`;
          await sql`INSERT INTO record_links (from_id, from_module, to_id, to_module, link_type) VALUES (${id}, 'ro', ${ncId}, 'nc', 'gerou_nc')`;
          newData.ncId = ncId; await sql`UPDATE records SET data=${JSON.stringify(newData)} WHERE id=${id}`;
          return res.json({ ok:true, ncId });
        } catch(e) { console.error('[ro->nc]', e.message); }
      }
      if (newData.decisaoFinal==='abrir_riacp' && newData.abrirRIACP && !currentData.riacpId) {
        try {
          const riacpId = await nextSequence('riacp');
          const riacpData = { id:riacpId, status:'aberto', tipo:'Corretivo', origem:['Registro de Ocorrencia'], descricao:newData.descricaoOcorrencia||'', origemRO:id, createdBy:user.id, createdByName:user.name, createdAt:new Date().toISOString(), acoes:[], log:[{at:new Date().toISOString(),by:user.name,event:'RIACP aberta a partir de '+id,detail:''}] };
          await sql`INSERT INTO records (id, module, status, data, created_by) VALUES (${riacpId}, 'riacp', 'aberto', ${JSON.stringify(riacpData)}, ${user.id})`;
          await sql`INSERT INTO record_links (from_id, from_module, to_id, to_module, link_type) VALUES (${id}, 'ro', ${riacpId}, 'riacp', 'gerou_riacp')`;
          newData.riacpId = riacpId; await sql`UPDATE records SET data=${JSON.stringify(newData)} WHERE id=${id}`;
          return res.json({ ok:true, riacpId });
        } catch(e) { console.error('[ro->riacp]', e.message); }
      }
      return res.json({ ok:true });
    } catch(err) { console.error('[PUT ro]', err); return res.status(500).json({ error: 'Erro ao atualizar RO', detail: err.message }); }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};