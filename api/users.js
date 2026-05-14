const bcrypt=require('bcryptjs');const jwt=require('jsonwebtoken');const{neon}=require('@neondatabase/serverless');
const sql=neon(process.env.DATABASE_URL);const SECRET=process.env.JWT_SECRET||'dev-secret';
const CORS=res=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');};
const vt=req=>{const a=req.headers.authorization||'';const t=a.startsWith('Bearer ')?a.slice(7):null;if(!t)return null;try{return jwt.verify(t,SECRET);}catch{return null;}};
const ra=(req,res)=>{const u=vt(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}return u;};
// Busca permissões do usuário no banco (admin sempre passa; outros precisam ter a permissão no grupo)
const userHasPerm=async(uid,perm)=>{const rows=await sql`SELECT r.permissions FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=${uid}`;for(const x of rows){const p=Array.isArray(x.permissions)?x.permissions:[];if(p.includes(perm))return true;}return false;};
// rad = "require admin/sgq" (versão antiga, mantida pra trás-compatibilidade)
// requirePerm = nova versão baseada em permissão de grupo
const requirePerm=async(req,res,perm)=>{const u=vt(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}if(u.role==='admin')return u;const ok=await userHasPerm(u.id,perm);if(!ok){res.status(403).json({error:'Sem permissao'});return null;}return u;};
const rad=(req,res)=>{const u=vt(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}if(!['admin','sgq'].includes(u.role)){res.status(403).json({error:'Sem permissao'});return null;}return u;};
const valPwd=(p,u={})=>{if(!p)return'Senha obrigatoria';if(p.length<8)return'Minimo 8 caracteres';if(p.length>20)return'Maximo 20 caracteres';if(!/[A-Z]/.test(p))return'Deve ter maiuscula';if(!/[a-z]/.test(p))return'Deve ter minuscula';if(!/[0-9]/.test(p))return'Deve ter numero';if(!/[^A-Za-z0-9]/.test(p))return'Deve ter caractere especial';const pl=p.toLowerCase();if(u.name){for(const x of u.name.toLowerCase().split(/\s+/).filter(s=>s.length>=3)){if(pl.includes(x))return'Senha nao pode conter seu nome';}}if(u.email){const el=u.email.toLowerCase().split('@')[0];if(el.length>=3&&pl.includes(el))return'Senha nao pode conter seu email';}return null;};
const ALLP=['dashboard','indicators','users','usuarios.gerenciar','usuarios.importar','grupos.ver','grupos.gerenciar','auditoria.ver','config.criticidades','config.matriz','config.perguntas','config.prazos','produtos.ver','produtos.gerenciar','sa.avaliacao_inicial','sa.criar','sa.ver_todas','sa.aprovacao_plano','sa.concluir','sa.cancelar','sa.abrir','sa.analisar','sa.aprovar','sa.fechar','sa.excluir','ro.abrir','ro.analisar','ro.tratar_segregado','ro.aprovar_concessao','ro.aprovar_correcao','ro.reatribuir_aprovador','ro.aprovar','ro.cancelar','ro.reabrir','ro.fechar','ro.excluir','ro.ver_todas','nc.abrir','nc.vincular_ro','nc.tratar_itens','nc.aprovar_concessao','nc.gerenciar_acoes','nc.concluir_acao','nc.analisar','nc.aprovar','nc.fechar','nc.cancelar','nc.reabrir','nc.excluir','nc.ver_todas','riacp.abrir','riacp.analisar','riacp.aprovar','riacp.fechar','riacp.excluir','riacp.ver_todas'];

module.exports=async(req,res)=>{
  CORS(res);if(req.method==='OPTIONS')return res.status(200).end();
  const{_route,id}=req.query||{};

  // ROLES
  if(_route==='roles'){
    // GET com ?id=USER_ID -> devolve grupos daquele usuário
    if(req.method==='GET' && id){
      const d=await requirePerm(req,res,'usuarios.gerenciar');if(!d)return;
      try{return res.json(await sql`SELECT r.id,r.name,r.description,r.permissions,r.is_system FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=${id} ORDER BY r.name`);}
      catch{return res.status(500).json({error:'Erro interno'});}
    }
    if(req.method==='GET'){
      const d=await requirePerm(req,res,'grupos.ver');if(!d)return;
      try{return res.json(await sql`SELECT r.id,r.name,r.description,r.permissions,r.is_system,r.created_at,COUNT(ur.user_id)::int as user_count FROM roles r LEFT JOIN user_roles ur ON ur.role_id=r.id GROUP BY r.id ORDER BY r.is_system DESC,r.name`);}
      catch{return res.status(500).json({error:'Erro interno'});}
    }
    if(req.method==='POST'){
      const d=await requirePerm(req,res,'grupos.gerenciar');if(!d)return;
      try{
        const{name,description,permissions}=req.body||{};
        if(!name?.trim())return res.status(400).json({error:'Nome obrigatorio'});
        const vp=(permissions||[]).filter(p=>ALLP.includes(p));
        const[r]=await sql`INSERT INTO roles(name,description,permissions,is_system,created_by)VALUES(${name.trim()},${description?.trim()||null},${JSON.stringify(vp)}::jsonb,false,${d.name})RETURNING id,name,description,permissions,is_system,created_at`;
        await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},'grupos','Grupo criado',${name})`;
        return res.status(201).json(r);
      }catch(e){if(e.message?.includes('unique'))return res.status(409).json({error:'Nome ja existe'});return res.status(500).json({error:'Erro interno'});}
    }
    if(req.method==='PUT'){
      const d=await requirePerm(req,res,'grupos.gerenciar');if(!d)return;
      try{
        const{id:rid,name,description,permissions}=req.body||{};
        const[ex]=await sql`SELECT is_system FROM roles WHERE id=${rid}`;
        if(!ex)return res.status(404).json({error:'Grupo nao encontrado'});
        const vp=(permissions||[]).filter(p=>ALLP.includes(p));
        if(ex.is_system){await sql`UPDATE roles SET description=${description?.trim()||null},permissions=${JSON.stringify(vp)}::jsonb WHERE id=${rid}`;}
        else{if(!name?.trim())return res.status(400).json({error:'Nome obrigatorio'});await sql`UPDATE roles SET name=${name.trim()},description=${description?.trim()||null},permissions=${JSON.stringify(vp)}::jsonb WHERE id=${rid}`;}
        await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},'grupos','Grupo editado',${name||'id='+rid})`;
        return res.json({ok:true});
      }catch{return res.status(500).json({error:'Erro interno'});}
    }
    if(req.method==='DELETE'){
      const d=await requirePerm(req,res,'grupos.gerenciar');if(!d)return;
      try{
        const{id:rid}=req.body||{};
        const[ex]=await sql`SELECT is_system,name FROM roles WHERE id=${rid}`;
        if(!ex)return res.status(404).json({error:'Grupo nao encontrado'});
        if(ex.is_system)return res.status(400).json({error:'Grupos do sistema nao podem ser excluidos'});
        const[{count}]=await sql`SELECT COUNT(*)::int as count FROM user_roles WHERE role_id=${rid}`;
        if(count>0)return res.status(400).json({error:`Grupo possui ${count} usuario(s). Remova-os antes.`});
        await sql`DELETE FROM roles WHERE id=${rid}`;
        await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},'grupos','Grupo excluido',${ex.name})`;
        return res.json({ok:true});
      }catch{return res.status(500).json({error:'Erro interno'});}
    }
  }

  // TROCAR PRÓPRIA SENHA
  if(_route==='me'&&req.method==='PUT'){
    const d=ra(req,res);if(!d)return;
    try{
      const{_curPwd,_np}=req.body||{};
      if(!_curPwd||!_np)return res.status(400).json({error:'Campos obrigatorios'});
      const[u]=await sql`SELECT pwd_hash,name,email FROM users WHERE id=${d.id}`;
      if(!await bcrypt.compare(_curPwd,u.pwd_hash))return res.status(401).json({error:'Senha atual incorreta'});
      const pe=valPwd(_np,{name:u.name,email:u.email});if(pe)return res.status(400).json({error:pe});
      if(await bcrypt.compare(_np,u.pwd_hash))return res.status(400).json({error:'Nova senha igual a atual'});
      const h=await bcrypt.hash(_np,10);
      await sql`UPDATE users SET pwd_hash=${h},pwd_hash_prev=${u.pwd_hash} WHERE id=${d.id}`;
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},'sistema','Senha alterada',${d.email})`;
      return res.json({ok:true});
    }catch{return res.status(500).json({error:'Erro interno'});}
  }

  // GET — listar usuários
  if(req.method==='GET'){
    const d=ra(req,res);if(!d)return;
    try{
      const rows=await sql`SELECT id,name,email,area,role,eval_depts,active,created_at FROM users ORDER BY name`;
      const ur=await sql`SELECT ur.user_id,r.id,r.name,r.permissions FROM user_roles ur JOIN roles r ON r.id=ur.role_id ORDER BY r.name`;
      const gU={},pU={};
      for(const x of ur){if(!gU[x.user_id])gU[x.user_id]=[];if(!pU[x.user_id])pU[x.user_id]=new Set();gU[x.user_id].push({id:x.id,name:x.name});(Array.isArray(x.permissions)?x.permissions:[]).forEach(p=>pU[x.user_id].add(p));}
      return res.json(rows.map(u=>({...u,evalDepts:u.eval_depts||[],groups:gU[u.id]||[],groupIds:(gU[u.id]||[]).map(g=>g.id),permissions:[...(pU[u.id]||[])]})));
    }catch{return res.status(500).json({error:'Erro interno'});}
  }

  // POST — criar usuário
  if(req.method==='POST'){
    const d=await requirePerm(req,res,'usuarios.gerenciar');if(!d)return;
    try{
      const{name,email,pwd,area,role,groupIds,evalDepts}=req.body||{};
      if(!name||!email||!pwd)return res.status(400).json({error:'Nome, email e senha obrigatorios'});
      const pe=valPwd(pwd,{name,email});if(pe)return res.status(400).json({error:pe});
      const h=await bcrypt.hash(pwd,10);
      const[u]=await sql`INSERT INTO users(name,email,area,role,pwd_hash,eval_depts,active,created_by)VALUES(${name},${email.toLowerCase().trim()},${area||''},${role||'geral'},${h},${JSON.stringify(evalDepts||[])}::jsonb,true,${d.name})RETURNING id,name,email,area,role,eval_depts,active`;
      if(Array.isArray(groupIds)){for(const g of groupIds)await sql`INSERT INTO user_roles(user_id,role_id)VALUES(${u.id},${g})ON CONFLICT DO NOTHING`;}
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},'usuarios','Usuario criado',${name+' ('+email+')'})`;
      return res.status(201).json({ok:true,user:u});
    }catch(e){if(e.message?.includes('unique'))return res.status(409).json({error:'Email ja cadastrado'});return res.status(500).json({error:'Erro interno'});}
  }

  // PUT — editar usuário
  if(req.method==='PUT'){
    const d=await requirePerm(req,res,'usuarios.gerenciar');if(!d)return;
    try{
      const{id:uid,name,email,pwd,area,role,groupIds,evalDepts,active}=req.body||{};
      if(!uid)return res.status(400).json({error:'ID obrigatorio'});
      if(pwd){
        const pe=valPwd(pwd,{name,email});if(pe)return res.status(400).json({error:pe});
        const[u]=await sql`SELECT pwd_hash FROM users WHERE id=${uid}`;
        const h=await bcrypt.hash(pwd,10);
        await sql`UPDATE users SET name=${name},email=${email.toLowerCase()},area=${area||''},role=${role||'geral'},eval_depts=${JSON.stringify(evalDepts||[])}::jsonb,active=${active!==false},pwd_hash=${h},pwd_hash_prev=${u.pwd_hash} WHERE id=${uid}`;
      }else{
        await sql`UPDATE users SET name=${name},email=${email.toLowerCase()},area=${area||''},role=${role||'geral'},eval_depts=${JSON.stringify(evalDepts||[])}::jsonb,active=${active!==false} WHERE id=${uid}`;
      }
      // Atualiza grupos: se groupIds veio (mesmo lista vazia), limpa e reinsere
      if(groupIds!==undefined && groupIds!==null){
        const ids=Array.isArray(groupIds)?groupIds:[];
        await sql`DELETE FROM user_roles WHERE user_id=${uid}`;
        for(const g of ids) await sql`INSERT INTO user_roles(user_id,role_id)VALUES(${uid},${g})ON CONFLICT DO NOTHING`;
      }
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},'usuarios','Usuario editado',${name+' (id='+uid+')'})`;
      return res.json({ok:true});
    }catch(e){if(e.message?.includes('unique'))return res.status(409).json({error:'Email ja cadastrado'});return res.status(500).json({error:'Erro interno'});}
  }

  return res.status(405).json({error:'Method not allowed'});
};
