// DELETAR APÓS O PRIMEIRO USO!
const bcrypt=require('bcryptjs');const{neon}=require('@neondatabase/serverless');
const sql=neon(process.env.DATABASE_URL);
const CORS=res=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');};
module.exports=async(req,res)=>{
  CORS(res);if(req.method==='OPTIONS')return res.status(200).end();
  const{token,email,pwd}=req.query;
  if(!token||token!==process.env.SETUP_TOKEN)return res.status(403).json({error:'Token invalido'});
  try{
    const fe=(email||'admin@vydence.com').toLowerCase(),fp=pwd||'Admin@123',h=await bcrypt.hash(fp,12);
    await sql`INSERT INTO roles(name,description,permissions,is_system)VALUES('Administradores','Acesso total','["dashboard","usuarios.gerenciar","grupos.gerenciar","auditoria.ver","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar"]'::jsonb,true),('SGQ','Equipe Qualidade','["dashboard","auditoria.ver","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar"]'::jsonb,true),('Geral','Usuario padrao','["dashboard","ro.abrir","nc.abrir","sa.abrir"]'::jsonb,true)ON CONFLICT(name)DO NOTHING`;
    const[ex]=await sql`SELECT id FROM users WHERE email=${fe}`;
    let uid;
    if(ex){await sql`UPDATE users SET pwd_hash=${h},role='admin',active=true WHERE id=${ex.id}`;uid=ex.id;}
    else{const[u]=await sql`INSERT INTO users(name,email,area,role,pwd_hash,eval_depts,active,created_by)VALUES('Administrador',${fe},'SGQ','admin',${h},'[]',true,'setup')RETURNING id`;uid=u.id;}
    const[ar]=await sql`SELECT id FROM roles WHERE name='Administradores' LIMIT 1`;
    if(ar)await sql`INSERT INTO user_roles(user_id,role_id)VALUES(${uid},${ar.id})ON CONFLICT DO NOTHING`;
    return res.json({ok:true,email:fe,message:'Admin criado! DELETE este arquivo agora.'});
  }catch(e){return res.status(500).json({error:e.message});}
};
