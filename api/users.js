const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const { sql } = require('../lib/db');
const { cors } = require('../lib/cors');
const { validatePassword } = require('../lib/passwordPolicy');
const { ALL_PERMISSIONS } = require('../lib/permissions');

const SECRET = process.env.JWT_SECRET||'dev-secret';
function verifyToken(req) {
  const auth = req.headers.authorization||'';
  const t = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!t) return null;
  try { return jwt.verify(t,SECRET); } catch { return null; }
}
function requireAuth(req,res) { const u=verifyToken(req); if(!u){res.status(401).json({error:'Nao autenticado'});return null;} return u; }
function requireAdmin(req,res) { const u=verifyToken(req); if(!u){res.status(401).json({error:'Nao autenticado'});return null;} if(!['admin','sgq'].includes(u.role)){res.status(403).json({error:'Sem permissao'});return null;} return u; }

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { _route, id } = req.query||{};

  /* ════ ROLES ════ */

  // GET /api/users?_route=roles
  if (_route === 'roles' && req.method === 'GET') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const rows = await sql`SELECT r.id,r.name,r.description,r.permissions,r.is_system,r.created_at,COUNT(ur.user_id)::int as user_count FROM roles r LEFT JOIN user_roles ur ON ur.role_id=r.id GROUP BY r.id ORDER BY r.is_system DESC,r.name`;
      return res.json(rows);
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // POST /api/users?_route=roles
  if (_route === 'roles' && req.method === 'POST') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const {name,description,permissions} = req.body||{};
      if (!name?.trim()) return res.status(400).json({error:'Nome obrigatorio'});
      const valid = (permissions||[]).filter(p=>ALL_PERMISSIONS.includes(p));
      const [r] = await sql`INSERT INTO roles(name,description,permissions,is_system,created_by) VALUES(${name.trim()},${description?.trim()||null},${JSON.stringify(valid)}::jsonb,false,${decoded.name}) RETURNING id,name,description,permissions,is_system,created_at`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'grupos','Grupo criado',${name})`;
      return res.status(201).json(r);
    } catch(err) {
      if(err.message?.includes('unique')) return res.status(409).json({error:'Nome ja existe'});
      return res.status(500).json({error:'Erro interno'});
    }
  }

  // PUT /api/users?_route=roles
  if (_route === 'roles' && req.method === 'PUT') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const {id:rid,name,description,permissions} = req.body||{};
      if (!rid) return res.status(400).json({error:'ID obrigatorio'});
      const [ex] = await sql`SELECT is_system FROM roles WHERE id=${rid}`;
      if (!ex) return res.status(404).json({error:'Grupo nao encontrado'});
      const valid = (permissions||[]).filter(p=>ALL_PERMISSIONS.includes(p));
      if (ex.is_system) {
        await sql`UPDATE roles SET description=${description?.trim()||null},permissions=${JSON.stringify(valid)}::jsonb WHERE id=${rid}`;
      } else {
        if (!name?.trim()) return res.status(400).json({error:'Nome obrigatorio'});
        await sql`UPDATE roles SET name=${name.trim()},description=${description?.trim()||null},permissions=${JSON.stringify(valid)}::jsonb WHERE id=${rid}`;
      }
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'grupos','Grupo editado',${name||'id='+rid})`;
      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // DELETE /api/users?_route=roles
  if (_route === 'roles' && req.method === 'DELETE') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const {id:rid} = req.body||{};
      const [ex] = await sql`SELECT is_system,name FROM roles WHERE id=${rid}`;
      if (!ex) return res.status(404).json({error:'Grupo nao encontrado'});
      if (ex.is_system) return res.status(400).json({error:'Grupos do sistema nao podem ser excluidos'});
      const [{count}] = await sql`SELECT COUNT(*)::int as count FROM user_roles WHERE role_id=${rid}`;
      if (count>0) return res.status(400).json({error:`Grupo possui ${count} usuario(s). Remova-os antes.`});
      await sql`DELETE FROM roles WHERE id=${rid}`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'grupos','Grupo excluido',${ex.name})`;
      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  /* ════ USERS ════ */

  // PUT /api/users?_route=me (trocar própria senha)
  if (_route === 'me' && req.method === 'PUT') {
    const decoded = requireAuth(req,res); if(!decoded) return;
    try {
      const {_curPwd,_np} = req.body||{};
      if (!_curPwd||!_np) return res.status(400).json({error:'Campos obrigatorios'});
      const [u] = await sql`SELECT pwd_hash,name,email FROM users WHERE id=${decoded.id}`;
      if (!await bcrypt.compare(_curPwd,u.pwd_hash)) return res.status(401).json({error:'Senha atual incorreta'});
      const pErr = validatePassword(_np,{name:u.name,email:u.email});
      if (pErr) return res.status(400).json({error:pErr});
      if (await bcrypt.compare(_np,u.pwd_hash)) return res.status(400).json({error:'Nova senha nao pode ser igual a atual'});
      const hash = await bcrypt.hash(_np,10);
      await sql`UPDATE users SET pwd_hash=${hash},pwd_hash_prev=${u.pwd_hash} WHERE id=${decoded.id}`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'sistema','Senha alterada pelo proprio usuario',${decoded.email})`;
      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // PUT /api/users?_route=userroles&id=X (atribuir grupos a usuário)
  if (_route === 'userroles' && id && req.method === 'PUT') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const {groupIds} = req.body||{};
      await sql`DELETE FROM user_roles WHERE user_id=${id}`;
      if (Array.isArray(groupIds)) {
        for (const gid of groupIds) await sql`INSERT INTO user_roles(user_id,role_id) VALUES(${id},${gid}) ON CONFLICT DO NOTHING`;
      }
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'usuarios','Grupos atualizados','user_id='+${id})`;
      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // GET /api/users — listar todos
  if (req.method === 'GET') {
    const decoded = requireAuth(req,res); if(!decoded) return;
    try {
      const rows = await sql`SELECT id,name,email,area,role,eval_depts,active,created_at FROM users ORDER BY name`;
      const urRows = await sql`SELECT ur.user_id,r.id,r.name,r.permissions FROM user_roles ur JOIN roles r ON r.id=ur.role_id ORDER BY r.name`;
      const gByU={}, pByU={};
      for (const ur of urRows) {
        if (!gByU[ur.user_id]) gByU[ur.user_id]=[];
        if (!pByU[ur.user_id]) pByU[ur.user_id]=new Set();
        gByU[ur.user_id].push({id:ur.id,name:ur.name});
        (Array.isArray(ur.permissions)?ur.permissions:[]).forEach(p=>pByU[ur.user_id].add(p));
      }
      return res.json(rows.map(u=>({...u,evalDepts:u.eval_depts||[],groups:gByU[u.id]||[],groupIds:(gByU[u.id]||[]).map(g=>g.id),permissions:[...(pByU[u.id]||[])]})));
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  // POST /api/users — criar
  if (req.method === 'POST') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const {name,email,pwd,area,role,groupIds,evalDepts} = req.body||{};
      if (!name||!email||!pwd) return res.status(400).json({error:'Nome, email e senha obrigatorios'});
      const pErr = validatePassword(pwd,{name,email});
      if (pErr) return res.status(400).json({error:pErr});
      const hash = await bcrypt.hash(pwd,10);
      const [created] = await sql`INSERT INTO users(name,email,area,role,pwd_hash,eval_depts,active,created_by) VALUES(${name},${email.toLowerCase().trim()},${area||''},${role||'geral'},${hash},${JSON.stringify(evalDepts||[])}::jsonb,true,${decoded.name}) RETURNING id,name,email,area,role,eval_depts,active`;
      if (Array.isArray(groupIds)) {
        for (const gid of groupIds) await sql`INSERT INTO user_roles(user_id,role_id) VALUES(${created.id},${gid}) ON CONFLICT DO NOTHING`;
      }
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'usuarios','Usuario criado',${name+' ('+email+')'})`;
      return res.status(201).json({ok:true,user:created});
    } catch(err) {
      if(err.message?.includes('unique')) return res.status(409).json({error:'Email ja cadastrado'});
      return res.status(500).json({error:'Erro interno'});
    }
  }

  // PUT /api/users — editar
  if (req.method === 'PUT') {
    const decoded = requireAdmin(req,res); if(!decoded) return;
    try {
      const {id:uid,name,email,pwd,area,role,groupIds,evalDepts,active} = req.body||{};
      if (!uid) return res.status(400).json({error:'ID obrigatorio'});
      if (pwd) {
        const pErr = validatePassword(pwd,{name,email});
        if (pErr) return res.status(400).json({error:pErr});
        const [u] = await sql`SELECT pwd_hash FROM users WHERE id=${uid}`;
        const hash = await bcrypt.hash(pwd,10);
        await sql`UPDATE users SET name=${name},email=${email.toLowerCase()},area=${area||''},role=${role||'geral'},eval_depts=${JSON.stringify(evalDepts||[])}::jsonb,active=${active!==false},pwd_hash=${hash},pwd_hash_prev=${u.pwd_hash} WHERE id=${uid}`;
      } else {
        await sql`UPDATE users SET name=${name},email=${email.toLowerCase()},area=${area||''},role=${role||'geral'},eval_depts=${JSON.stringify(evalDepts||[])}::jsonb,active=${active!==false} WHERE id=${uid}`;
      }
      if (Array.isArray(groupIds)) {
        await sql`DELETE FROM user_roles WHERE user_id=${uid}`;
        for (const gid of groupIds) await sql`INSERT INTO user_roles(user_id,role_id) VALUES(${uid},${gid}) ON CONFLICT DO NOTHING`;
      }
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${decoded.name},'usuarios','Usuario editado',${name+' (id='+uid+')'})`;
      return res.json({ok:true});
    } catch(err) {
      if(err.message?.includes('unique')) return res.status(409).json({error:'Email ja cadastrado'});
      return res.status(500).json({error:'Erro interno'});
    }
  }

  return res.status(405).json({error:'Method not allowed'});
};
