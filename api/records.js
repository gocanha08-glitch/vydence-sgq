const jwt = require('jsonwebtoken');
const { sql } = require('../lib/db');
const { cors } = require('../lib/cors');

const SECRET = process.env.JWT_SECRET||'dev-secret';
function verifyToken(req) {
  const auth=req.headers.authorization||'';
  const t=auth.startsWith('Bearer ')?auth.slice(7):null;
  if(!t)return null;
  try{return jwt.verify(t,SECRET);}catch{return null;}
}
function requireAuth(req,res){const u=verifyToken(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}return u;}

const MODULE_STATUS = {
  ro:    ['Aberto','Em Análise','Aprovado','Fechado'],
  nc:    ['Aberto','Em Análise','Plano de Ação','Aprovado','Fechado'],
  riacp: ['Identificação','Análise de Causa','Plano de Ação','Verificação','Encerrado'],
  sa:    ['Solicitado','Avaliação','Aprovado','Implementação','Verificação','Encerrado'],
};

async function nextCode(module) {
  const year = new Date().getFullYear();
  await sql`INSERT INTO sequences(module,year,last) VALUES(${module},${year},0) ON CONFLICT(module,year) DO NOTHING`;
  const [row] = await sql`UPDATE sequences SET last=last+1 WHERE module=${module} AND year=${year} RETURNING last`;
  return `${module.toUpperCase()}-${String(row.last).padStart(3,'0')}/${year}`;
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = requireAuth(req,res); if(!decoded) return;
  const { module, id } = req.query||{};

  if (!module||!MODULE_STATUS[module]) return res.status(400).json({error:'Modulo invalido. Use: ro, nc, riacp ou sa'});

  const steps  = MODULE_STATUS[module];
  const isAdmin = ['admin','sgq'].includes(decoded.role);
  const perms   = decoded.permissions||[];

  // GET — listar
  if (req.method === 'GET' && !id) {
    try {
      const rows = await sql`SELECT r.id,r.code,r.module,r.title,r.description,r.status,r.priority,r.data,r.owner_name,r.created_at,r.updated_at,u.name as creator_name FROM records r LEFT JOIN users u ON u.id=r.created_by WHERE r.module=${module} ORDER BY r.created_at DESC`;
      return res.json(rows);
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // GET — por ID
  if (req.method === 'GET' && id) {
    try {
      const [record] = await sql`SELECT * FROM records WHERE id=${id} AND module=${module}`;
      if (!record) return res.status(404).json({error:'Registro nao encontrado'});
      const actions    = await sql`SELECT * FROM actions WHERE record_id=${id} ORDER BY created_at`;
      const signatures = await sql`SELECT * FROM signatures WHERE record_id=${record.code} ORDER BY signed_at DESC`;
      return res.json({...record,actions,signatures});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // POST — criar
  if (req.method === 'POST') {
    if (!isAdmin && !perms.includes(`${module}.abrir`))
      return res.status(403).json({error:'Sem permissao para abrir registros neste modulo'});
    try {
      const {title,description,priority,data} = req.body||{};
      if (!title?.trim()) return res.status(400).json({error:'Titulo obrigatorio'});
      const code   = await nextCode(module);
      const status = steps[0];
      const [record] = await sql`INSERT INTO records(code,module,title,description,status,priority,data,owner_id,owner_name,created_by) VALUES(${code},${module},${title.trim()},${description||''},${status},${priority||'media'},${JSON.stringify(data||{})}::jsonb,${decoded.id},${decoded.name},${decoded.id}) RETURNING id,code,module,title,description,status,priority,owner_name,created_at`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},${module},${'Registro aberto: '+code},${title})`;
      return res.status(201).json(record);
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // PUT — atualizar
  if (req.method === 'PUT' && id) {
    try {
      const [existing] = await sql`SELECT * FROM records WHERE id=${id} AND module=${module}`;
      if (!existing) return res.status(404).json({error:'Registro nao encontrado'});
      const {status,data,title,description,priority} = req.body||{};

      if (status && status !== existing.status) {
        if (steps.indexOf(status) === -1) return res.status(400).json({error:'Status invalido'});
        const needPerm = steps.indexOf(status) >= steps.length-1 ? `${module}.fechar` : `${module}.analisar`;
        if (!isAdmin && !perms.includes(needPerm)) return res.status(403).json({error:'Sem permissao para esta transicao'});
      }

      await sql`UPDATE records SET status=${status||existing.status},title=${title||existing.title},description=${description??existing.description},priority=${priority||existing.priority},data=${JSON.stringify(data||existing.data)}::jsonb,updated_at=now() WHERE id=${id}`;

      if (status && status !== existing.status)
        await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},${module},${'Status: '+existing.status+' → '+status},${existing.code})`;

      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // DELETE
  if (req.method === 'DELETE' && id) {
    if (!isAdmin && !perms.includes(`${module}.excluir`)) return res.status(403).json({error:'Sem permissao'});
    try {
      const [existing] = await sql`SELECT code FROM records WHERE id=${id}`;
      if (!existing) return res.status(404).json({error:'Nao encontrado'});
      await sql`DELETE FROM actions WHERE record_id=${id}`;
      await sql`DELETE FROM records WHERE id=${id}`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},${module},'Registro excluido',${existing.code})`;
      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  return res.status(405).json({error:'Method not allowed'});
};
