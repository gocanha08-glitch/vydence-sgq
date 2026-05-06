const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
const { sql } = require('../lib/db');
const { cors } = require('../lib/cors');
const { validatePassword } = require('../lib/passwordPolicy');
const { sendResetPassword } = require('../lib/email/mailer');

const SECRET = process.env.JWT_SECRET || 'dev-secret';

function signToken(user) {
  return jwt.sign(
    { id:user.id, email:user.email, role:user.role, name:user.name,
      permissions:user.permissions||[], groups:user.groups||[], area:user.area||'' },
    SECRET, { expiresIn:'8h' }
  );
}
function verifyToken(req) {
  const auth = req.headers.authorization||'';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  try { return jwt.verify(token, SECRET); } catch { return null; }
}

const rateLimitMap = new Map();
function checkRL(req, res) {
  const ip  = req.headers['x-forwarded-for']?.split(',')[0]?.trim()||'unknown';
  const now = Date.now();
  const e   = rateLimitMap.get(ip)||{count:0,start:now};
  if (now - e.start > 60000) { rateLimitMap.set(ip,{count:1,start:now}); return false; }
  if (e.count >= 10) { res.setHeader('Retry-After','60'); res.status(429).json({error:'Muitas tentativas. Aguarde 1 minuto.'}); return true; }
  e.count++; rateLimitMap.set(ip,e); return false;
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const route = req.query._route || '';

  /* ── POST /api/auth?_route=login ── */
  if (req.method === 'POST' && route === 'login') {
    if (checkRL(req,res)) return;
    try {
      const { email, password } = req.body||{};
      if (!email||!password) return res.status(400).json({error:'Email e senha obrigatorios'});

      const rows = await sql`SELECT id,name,email,area,role,pwd_hash,eval_depts,active,locked_until,login_attempts FROM users WHERE email=${email.toLowerCase().trim()} LIMIT 1`;
      const user = rows[0];
      if (!user||!user.active) return res.status(401).json({error:'Usuario nao encontrado ou inativo'});

      if (user.locked_until && new Date(user.locked_until) > new Date())
        return res.status(401).json({error:'Conta bloqueada temporariamente.'});

      const valid = await bcrypt.compare(password, user.pwd_hash);
      if (!valid) {
        const attempts = (user.login_attempts||0)+1;
        if (attempts >= 5) {
          const lock = new Date(Date.now()+15*60000).toISOString();
          await sql`UPDATE users SET login_attempts=${attempts},locked_until=${lock} WHERE id=${user.id}`;
          return res.status(401).json({error:'Conta bloqueada por 15 minutos.'});
        }
        await sql`UPDATE users SET login_attempts=${attempts} WHERE id=${user.id}`;
        return res.status(401).json({error:'Senha incorreta'});
      }

      await sql`UPDATE users SET login_attempts=0,locked_until=null WHERE id=${user.id}`;

      const roleRows = await sql`SELECT r.id,r.name,r.permissions FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=${user.id} ORDER BY r.name`;
      const groups      = roleRows.map(r=>({id:r.id,name:r.name}));
      const permissions = [...new Set(roleRows.flatMap(r=>Array.isArray(r.permissions)?r.permissions:[]))];

      const userData = {id:user.id,name:user.name,email:user.email,area:user.area,role:user.role,
        evalDepts:user.eval_depts||[],permissions,groups,groupIds:groups.map(g=>g.id)};
      const token = signToken(userData);

      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${user.name},'sistema','Login',${user.email})`;
      return res.json({token,user:userData});
    } catch(err) { console.error(err); return res.status(500).json({error:'Erro interno'}); }
  }

  /* ── POST /api/auth?_route=forgot ── */
  if (req.method === 'POST' && route === 'forgot') {
    try {
      const { email } = req.body||{};
      if (!email) return res.status(400).json({error:'Email obrigatorio'});
      const rows = await sql`SELECT id,name FROM users WHERE email=${email.toLowerCase().trim()} AND active=true LIMIT 1`;
      if (!rows.length) return res.json({ok:true});
      const user  = rows[0];
      const token = crypto.randomBytes(32).toString('hex');
      const exp   = new Date(Date.now()+3600000).toISOString();
      await sql`UPDATE users SET reset_token=${token},reset_expires=${exp} WHERE id=${user.id}`;
      await sendResetPassword({to:email,name:user.name,resetUrl:`${process.env.APP_URL}/reset?token=${token}`});
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${user.name},'sistema','Reset senha solicitado',${email})`;
      return res.json({ok:true});
    } catch(err) { return res.status(500).json({error:'Erro interno'}); }
  }

  /* ── POST /api/auth?_route=reset ── */
  if (req.method === 'POST' && route === 'reset') {
    try {
      const { token, pwd } = req.body||{};
      if (!token||!pwd) return res.status(400).json({error:'Token e senha obrigatorios'});
      const rows = await sql`SELECT id,name,email,pwd_hash,pwd_hash_prev FROM users WHERE reset_token=${token} AND reset_expires>now() AND active=true LIMIT 1`;
      if (!rows.length) return res.status(400).json({error:'Token invalido ou expirado'});
      const user = rows[0];

      const policyErr = validatePassword(pwd,{name:user.name,email:user.email});
      if (policyErr) return res.status(400).json({error:policyErr});

      if (await bcrypt.compare(pwd,user.pwd_hash)) return res.status(400).json({error:'Nova senha nao pode ser igual a atual'});
      if (user.pwd_hash_prev && await bcrypt.compare(pwd,user.pwd_hash_prev)) return res.status(400).json({error:'Nova senha nao pode ser igual a ultima utilizada'});

      const hash = await bcrypt.hash(pwd,12);
      await sql`UPDATE users SET pwd_hash=${hash},pwd_hash_prev=${user.pwd_hash},reset_token=null,reset_expires=null,login_attempts=0,locked_until=null WHERE id=${user.id}`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${user.name},'sistema','Senha redefinida via reset',${user.email})`;
      return res.json({ok:true});
    } catch(err) { return res.status(500).json({error:'Erro interno'}); }
  }

  /* ── POST /api/auth?_route=verify ── */
  if (req.method === 'POST' && route === 'verify') {
    try {
      const decoded = verifyToken(req);
      if (!decoded) return res.status(401).json({error:'Nao autenticado'});
      const { password, record_id, action, action_detail, meaning } = req.body||{};
      if (!password||!action) return res.status(400).json({error:'Senha e acao obrigatorios'});

      const [user] = await sql`SELECT id,name,email,pwd_hash FROM users WHERE id=${decoded.id} AND active=true`;
      if (!user) return res.status(401).json({error:'Usuario nao encontrado'});
      if (!await bcrypt.compare(password,user.pwd_hash)) return res.status(401).json({error:'Senha incorreta'});

      const signedAt  = new Date().toISOString();
      const hash      = crypto.createHash('sha256').update(`${record_id||''}|${action}|${user.id}|${signedAt}`).digest('hex');
      const ip        = req.headers['x-forwarded-for']?.split(',')[0]?.trim()||null;
      const [ins] = await sql`INSERT INTO signatures(record_id,action,action_detail,signed_by_id,signed_by,signed_at,ip_address,user_agent,meaning,hash) VALUES(${record_id||null},${action},${action_detail||null},${user.id},${user.name},${signedAt},${ip},${req.headers['user-agent']||null},${meaning||action},${hash}) RETURNING id`;
      await sql`INSERT INTO syslog(by,type,event,detail) VALUES(${user.name},'assinatura',${action},${action_detail||''})`;
      return res.json({ok:true,signature:{signatureId:ins.id,signedByName:user.name,signedAt,hash,action}});
    } catch(err) { return res.status(500).json({error:'Erro interno'}); }
  }

  /* ── GET /api/auth?_route=me ── */
  if (req.method === 'GET' && route === 'me') {
    try {
      const decoded = verifyToken(req);
      if (!decoded) return res.status(401).json({error:'Nao autenticado'});
      const [u] = await sql`SELECT id,name,email,area,role,eval_depts,active FROM users WHERE id=${decoded.id}`;
      const roleRows = await sql`SELECT r.id,r.name,r.permissions FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=${decoded.id} ORDER BY r.name`;
      const groups      = roleRows.map(r=>({id:r.id,name:r.name}));
      const permissions = [...new Set(roleRows.flatMap(r=>Array.isArray(r.permissions)?r.permissions:[]))];
      return res.json({...u,groups,groupIds:groups.map(g=>g.id),permissions});
    } catch(err) { return res.status(500).json({error:'Erro interno'}); }
  }

  return res.status(405).json({error:'Method not allowed'});
};
