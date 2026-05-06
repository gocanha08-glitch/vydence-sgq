// DELETAR ESTE ARQUIVO APÓS O PRIMEIRO USO!
const bcrypt = require('bcryptjs');
const { sql } = require('../lib/db');
const { cors } = require('../lib/cors');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { token, email, pwd } = req.query;
  if (!token || token !== process.env.SETUP_TOKEN)
    return res.status(403).json({error:'Token invalido'});

  try {
    const finalEmail = (email||'admin@vydence.com').toLowerCase();
    const finalPwd   = pwd||'Admin@123';
    const hash = await bcrypt.hash(finalPwd, 12);

    await sql`INSERT INTO roles(name,description,permissions,is_system) VALUES
      ('Administradores','Acesso total','["dashboard","usuarios.gerenciar","grupos.gerenciar","auditoria.ver","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar"]'::jsonb,true),
      ('SGQ','Equipe Qualidade','["dashboard","auditoria.ver","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar"]'::jsonb,true),
      ('Geral','Usuario padrao','["dashboard","ro.abrir","nc.abrir","sa.abrir"]'::jsonb,true)
      ON CONFLICT(name) DO NOTHING`;

    const [ex] = await sql`SELECT id FROM users WHERE email=${finalEmail}`;
    let uid;
    if (ex) {
      await sql`UPDATE users SET pwd_hash=${hash},role='admin',active=true WHERE id=${ex.id}`;
      uid = ex.id;
    } else {
      const [u] = await sql`INSERT INTO users(name,email,area,role,pwd_hash,eval_depts,active,created_by) VALUES('Administrador',${finalEmail},'SGQ','admin',${hash},'[]',true,'setup') RETURNING id`;
      uid = u.id;
    }

    const [adminRole] = await sql`SELECT id FROM roles WHERE name='Administradores' LIMIT 1`;
    if (adminRole) await sql`INSERT INTO user_roles(user_id,role_id) VALUES(${uid},${adminRole.id}) ON CONFLICT DO NOTHING`;

    return res.json({ok:true, email:finalEmail, message:'Admin criado! DELETE este arquivo agora.'});
  } catch(err) {
    return res.status(500).json({error:err.message});
  }
};
