const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { hasPermission } = require('../../lib/permissions');
const { saveSignature } = require('../../lib/signatures');
const { nextSequence } = require('../../lib/sequences');
const cors = require('../../lib/cors');
const NC_STATUS = ['aberto','em_analise','aguardando_disposicao','em_execucao','concluido','cancelado'];
const LABELS = { em_analise:{action:'analise',detail:'NC em Analise',meaning:'Confirmo inicio da analise'}, aguardando_disposicao:{action:'disposicao',detail:'Aguardando disposicao',meaning:'Confirmo analise e acoes'}, em_execucao:{action:'execucao',detail:'NC em execucao',meaning:'Confirmo liberacao das acoes'}, concluido:{action:'conclusao',detail:'NC Concluida',meaning:'Confirmo encerramento desta NC'}, cancelado:{action:'cancelamento',detail:'NC Cancelada',meaning:'Confirmo cancelamento'} };
module.exports = async (req, res) => {
  cors(req, res); if (req.method === 'OPTIONS') return res.status(200).end();
  const user = requireAuth(req, res); if (!user) return;
  const { id } = req.query; if (!id) return res.status(400).json({ error: 'ID obrigatorio' });
  if (req.method === 'GET') {
    try {
      const rows = await sql`SELECT data FROM records WHERE id=${id} AND module='nc' LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ error: 'NC nao encontrada' });
      return res.json(rows[0].data);
    } catch { return res.status(500).json({ error: 'Erro ao buscar NC' }); }
  }
  if (req.method === 'PUT') {
    try {
      const newData = req.body; if (!newData) return res.status(400).json({ error: 'Dados invalidos' });
      const rows = await sql`SELECT data FROM records WHERE id=${id} AND module='nc' LIMIT 1`;
      if (!rows[0]) return res.status(404).json({ error: 'NC nao encontrada' });
      const currentData = rows[0].data;
      const oldStatus = currentData.status||'aberto'; const newStatus = newData.status||oldStatus;
      if (!NC_STATUS.includes(newStatus)) return res.status(400).json({ error: 'Status invalido' });
      if ((oldStatus==='concluido'||oldStatus==='cancelado') && newStatus!==oldStatus) return res.status(403).json({ error: 'NC encerrada nao pode ser alterada' });
      const log = [...(newData.log||currentData.log||[])];
      if (oldStatus!==newStatus) log.push({ at:new Date().toISOString(), by:user.name, event:oldStatus+' -> '+newStatus, detail:newData.logNote||'' });
      newData.log = log; newData.updatedAt = new Date().toISOString();
      await sql`UPDATE records SET data=${JSON.stringify(newData)}, status=${newStatus}, updated_at=now() WHERE id=${id}`;
      if (oldStatus!==newStatus) { const lbl=LABELS[newStatus]||{action:newStatus,detail:'Status: '+newStatus,meaning:'Confirmo'}; await saveSignature(req,{recordId:id,module:'nc',userId:user.id,userName:user.name,...lbl}); }
      if (newData.necessarioRIACP==='Sim' && newData.abrirRIACP && !currentData.riacpId) {
        try {
          const riacpId = await nextSequence('riacp');
          const riacpData = { id:riacpId, status:'aberto', tipo:'Corretivo', origem:['Nao Conformidade'], descricao:newData.descricaoNC||'', origemNC:id, origemRO:newData.origemRO||null, createdBy:user.id, createdByName:user.name, createdAt:new Date().toISOString(), acoes:[], log:[{at:new Date().toISOString(),by:user.name,event:'RIACP aberta a partir de '+id,detail:''}] };
          await sql`INSERT INTO records (id, module, status, data, created_by) VALUES (${riacpId}, 'riacp', 'aberto', ${JSON.stringify(riacpData)}, ${user.id})`;
          await sql`INSERT INTO record_links (from_id, from_module, to_id, to_module, link_type) VALUES (${id}, 'nc', ${riacpId}, 'riacp', 'gerou_riacp')`;
          newData.riacpId = riacpId; await sql`UPDATE records SET data=${JSON.stringify(newData)} WHERE id=${id}`;
          return res.json({ ok:true, riacpId });
        } catch(e) { console.error('[nc->riacp]', e.message); }
      }
      return res.json({ ok:true });
    } catch(err) { return res.status(500).json({ error: 'Erro ao atualizar NC', detail: err.message }); }
  }
  return res.status(405).json({ error: 'Method not allowed' });
};