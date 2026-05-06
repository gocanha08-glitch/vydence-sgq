const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');
const sql = neon(process.env.DATABASE_URL);
const SECRET = process.env.JWT_SECRET||'dev-secret';
const CORS = res => { res.setHeader('Access-Control-Allow-Origin','*'); res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization'); };
const vt = req => { const a=(req.headers.authorization||''); const t=a.startsWith('Bearer ')?a.slice(7):null; if(!t)return null; try{return jwt.verify(t,SECRET);}catch{return null;} };
const signToken = u => jwt.sign({id:u.id,email:u.email,role:u.role,name:u.name,permissions:u.permissions||[],groups:u.groups||[],area:u.area||''},SECRET,{expiresIn:'8h'});
const valPwd = (p,u={}) => { if(!p)return'Senha obrigatoria'; if(p.length<8)return'Minimo 8 caracteres'; if(p.length>20)return'Maximo 20 caracteres'; if(!/[A-Z]/.test(p))return'Deve ter maiuscula'; if(!/[a-z]/.test(p))return'Deve ter minuscula'; if(!/[0-9]/.test(p))return'Deve ter numero'; if(!/[^A-Za-z0-9]/.test(p))return'Deve ter caractere especial'; const pl=p.toLowerCase(); if(u.name){for(const x of u.name.toLowerCase().split(/\s+/).filter(s=>s.length>=3)){if(pl.includes(x))return'Senha nao pode conter seu nome';}} if(u.email){const el=u.email.toLowerCase().split('@')[0];if(el.length>=3&&pl.includes(el))return'Senha nao pode conter seu email';} return null; };
const rl=new Map();
const checkRL=(req,res)=>{ const ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||'x'; const now=Date.now(); const e=rl.get(ip)||{c:0,s:now}; if(now-e.s>60000){rl.set(ip,{c:1,s:now});return false;} if(e.c>=10){res.setHeader('Retry-After','60');res.status(429).json({error:'Muitas tentativas'});return true;} e.c++;rl.set(ip,e);return false; };
module.exports = async (req,res) => {
  CORS(res); if(req.method==='OPTIONS')return res.status(200).end();
  const r=req.query._route||'';
  if(req.method==='POST'&&r==='login'){
    if(checkRL(req,res))return;
    try{
      const{email,password}=req.body||{};
      if(!email||!password)return res.status(400).json({error:'Email e senha obrigatorios'});
      const rows=await sql`SELECT id,name,email,area,role,pwd_hash,eval_depts,active,locked_until,login_attempts FROM users WHERE email=${email.toLowerCase().trim()} LIMIT 1`;
      const u=rows[0];
      if(!u||!u.active)return res.status(401).json({error:'Usuario nao encontrado ou inativo'});
      if(u.locked_until&&new Date(u.locked_until)>new Date())return res.status(401).json({error:'Conta bloqueada temporariamente'});
      if(!await bcrypt.compare(password,u.pwd_hash)){
        const att=(u.login_attempts||0)+1;
        if(att>=5){await sql`UPDATE users SET login_attempts=${att},locked_until=${new Date(Date.now()+15*60000).toISOString()} WHERE id=${u.id}`;return res.status(401).json({error:'Conta bloqueada por 15 minutos'});}
        await sql`UPDATE users SET login_attempts=${att} WHERE id=${u.id}`;
        return res.status(401).json({error:'Senha incorreta'});
      }
      await sql`UPDATE users SET login_attempts=0,locked_until=null WHERE id=${u.id}`;
      const rr=await sql`SELECT r.id,r.name,r.permissions FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=${u.id}`;
      const groups=rr.map(x=>({id:x.id,name:x.name}));
      const permissions=[...new Set(rr.flatMap(x=>Array.isArray(x.permissions)?x.permissions:[]))];
      const ud={id:u.id,name:u.name,email:u.email,area:u.area,role:u.role,evalDepts:u.eval_depts||[],permissions,groups,groupIds:groups.map(g=>g.id)};
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${u.name},'sistema','Login',${u.email})`;
      return res.json({token:signToken(ud),user:ud});
    }catch(e){console.error(e);return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='POST'&&r==='forgot'){
    try{
      const{email}=req.body||{};
      if(!email)return res.status(400).json({error:'Email obrigatorio'});
      const rows=await sql`SELECT id,name FROM users WHERE email=${email.toLowerCase().trim()} AND active=true LIMIT 1`;
      if(!rows.length)return res.json({ok:true});
      const u=rows[0],tok=crypto.randomBytes(32).toString('hex'),exp=new Date(Date.now()+3600000).toISOString();
      await sql`UPDATE users SET reset_token=${tok},reset_expires=${exp} WHERE id=${u.id}`;
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${u.name},'sistema','Reset solicitado',${email})`;
      // email enviado se RESEND_API_KEY configurado
      if(process.env.RESEND_API_KEY){
        await fetch('https://api.resend.com/emails',{method:'POST',headers:{'Authorization':'Bearer '+process.env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:'SGQ Vydence <noreply@vydence.com>',to:[process.env.DEV_EMAIL||email],subject:'SGQ — Redefinição de senha',html:`<p>Olá ${u.name},</p><p><a href="${process.env.APP_URL}/reset?token=${tok}">Clique aqui para redefinir sua senha</a> (válido por 1 hora)</p>`})});
      }
      return res.json({ok:true});
    }catch(e){return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='POST'&&r==='reset'){
    try{
      const{token,pwd}=req.body||{};
      if(!token||!pwd)return res.status(400).json({error:'Token e senha obrigatorios'});
      const rows=await sql`SELECT id,name,email,pwd_hash,pwd_hash_prev FROM users WHERE reset_token=${token} AND reset_expires>now() AND active=true LIMIT 1`;
      if(!rows.length)return res.status(400).json({error:'Token invalido ou expirado'});
      const u=rows[0],pe=valPwd(pwd,{name:u.name,email:u.email});
      if(pe)return res.status(400).json({error:pe});
      if(await bcrypt.compare(pwd,u.pwd_hash))return res.status(400).json({error:'Nova senha igual a atual'});
      if(u.pwd_hash_prev&&await bcrypt.compare(pwd,u.pwd_hash_prev))return res.status(400).json({error:'Nova senha igual a ultima utilizada'});
      const h=await bcrypt.hash(pwd,12);
      await sql`UPDATE users SET pwd_hash=${h},pwd_hash_prev=${u.pwd_hash},reset_token=null,reset_expires=null,login_attempts=0,locked_until=null WHERE id=${u.id}`;
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${u.name},'sistema','Senha redefinida',${u.email})`;
      return res.json({ok:true});
    }catch(e){return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='POST'&&r==='verify'){
    try{
      const dec=vt(req); if(!dec)return res.status(401).json({error:'Nao autenticado'});
      const{password,record_id,action,action_detail,meaning}=req.body||{};
      if(!password||!action)return res.status(400).json({error:'Senha e acao obrigatorios'});
      const[u]=await sql`SELECT id,name,email,pwd_hash FROM users WHERE id=${dec.id} AND active=true`;
      if(!u)return res.status(401).json({error:'Usuario nao encontrado'});
      if(!await bcrypt.compare(password,u.pwd_hash))return res.status(401).json({error:'Senha incorreta'});
      const sat=new Date().toISOString(),h=crypto.createHash('sha256').update(`${record_id||''}|${action}|${u.id}|${sat}`).digest('hex');
      const ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||null;
      const[ins]=await sql`INSERT INTO signatures(record_id,action,action_detail,signed_by_id,signed_by,signed_at,ip_address,user_agent,meaning,hash)VALUES(${record_id||null},${action},${action_detail||null},${u.id},${u.name},${sat},${ip},${req.headers['user-agent']||null},${meaning||action},${h})RETURNING id`;
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${u.name},'assinatura',${action},${action_detail||''})`;
      return res.json({ok:true,signature:{signatureId:ins.id,signedByName:u.name,signedAt:sat,hash:h,action}});
    }catch(e){return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='GET'&&r==='me'){
    try{
      const dec=vt(req); if(!dec)return res.status(401).json({error:'Nao autenticado'});
      const[u]=await sql`SELECT id,name,email,area,role,eval_depts,active FROM users WHERE id=${dec.id}`;
      const rr=await sql`SELECT r.id,r.name,r.permissions FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=${dec.id}`;
      const groups=rr.map(x=>({id:x.id,name:x.name}));
      const permissions=[...new Set(rr.flatMap(x=>Array.isArray(x.permissions)?x.permissions:[]))];
      return res.json({...u,groups,groupIds:groups.map(g=>g.id),permissions});
    }catch(e){return res.status(500).json({error:'Erro interno'});}
  }
  return res.status(405).json({error:'Method not allowed'});
};
