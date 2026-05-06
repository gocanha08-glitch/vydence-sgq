const jwt=require('jsonwebtoken');const{neon}=require('@neondatabase/serverless');
const sql=neon(process.env.DATABASE_URL);const SECRET=process.env.JWT_SECRET||'dev-secret';
const CORS=res=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');};
const vt=req=>{const a=req.headers.authorization||'';const t=a.startsWith('Bearer ')?a.slice(7):null;if(!t)return null;try{return jwt.verify(t,SECRET);}catch{return null;}};
const ra=(req,res)=>{const u=vt(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}return u;};
module.exports=async(req,res)=>{
  CORS(res);if(req.method==='OPTIONS')return res.status(200).end();
  const d=ra(req,res);if(!d)return;
  const key=req.query.key;if(!key)return res.status(400).json({error:'Chave obrigatoria'});
  if(req.method==='GET'){
    try{
      if(key==='syslog'){return res.json(await sql`SELECT id,at,by,type,event,detail FROM syslog ORDER BY at DESC LIMIT 200`);}
      const rows=await sql`SELECT value FROM config WHERE key=${key} LIMIT 1`;
      return res.json(rows[0]?rows[0].value:null);
    }catch{return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='PUT'){
    try{
      const{value}=req.body||{};
      if(key==='syslog'){const es=Array.isArray(value)?value:[value];for(const e of es)await sql`INSERT INTO syslog(at,by,type,event,detail)VALUES(${e.at||new Date().toISOString()},${e.by||''},${e.type||'sistema'},${e.event||''},${e.detail||''})`;return res.json({ok:true});}
      await sql`INSERT INTO config(key,value,updated_at,updated_by)VALUES(${key},${JSON.stringify(value)}::jsonb,now(),${d.name})ON CONFLICT(key)DO UPDATE SET value=EXCLUDED.value,updated_at=now(),updated_by=EXCLUDED.updated_by`;
      return res.json({ok:true});
    }catch{return res.status(500).json({error:'Erro interno'});}
  }
  return res.status(405).json({error:'Method not allowed'});
};
