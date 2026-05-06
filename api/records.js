const jwt=require('jsonwebtoken');const{neon}=require('@neondatabase/serverless');
const sql=neon(process.env.DATABASE_URL);const SECRET=process.env.JWT_SECRET||'dev-secret';
const CORS=res=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');};
const vt=req=>{const a=req.headers.authorization||'';const t=a.startsWith('Bearer ')?a.slice(7):null;if(!t)return null;try{return jwt.verify(t,SECRET);}catch{return null;}};
const ra=(req,res)=>{const u=vt(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}return u;};
const MS={ro:['Aberto','Em Análise','Aprovado','Fechado'],nc:['Aberto','Em Análise','Plano de Ação','Aprovado','Fechado'],riacp:['Identificação','Análise de Causa','Plano de Ação','Verificação','Encerrado'],sa:['Solicitado','Avaliação','Aprovado','Implementação','Verificação','Encerrado']};
const nextCode=async mod=>{const y=new Date().getFullYear();await sql`INSERT INTO sequences(module,year,last)VALUES(${mod},${y},0)ON CONFLICT(module,year)DO NOTHING`;const[r]=await sql`UPDATE sequences SET last=last+1 WHERE module=${mod} AND year=${y} RETURNING last`;return`${mod.toUpperCase()}-${String(r.last).padStart(3,'0')}/${y}`;};

module.exports=async(req,res)=>{
  CORS(res);if(req.method==='OPTIONS')return res.status(200).end();
  const d=ra(req,res);if(!d)return;
  const{module:mod,id}=req.query||{};
  if(!mod||!MS[mod])return res.status(400).json({error:'Modulo invalido. Use: ro, nc, riacp ou sa'});
  const steps=MS[mod],isAdm=['admin','sgq'].includes(d.role),perms=d.permissions||[];

  if(req.method==='GET'&&!id){
    try{return res.json(await sql`SELECT r.id,r.code,r.module,r.title,r.description,r.status,r.priority,r.data,r.owner_name,r.created_at,r.updated_at,u.name as creator_name FROM records r LEFT JOIN users u ON u.id=r.created_by WHERE r.module=${mod} ORDER BY r.created_at DESC`);}
    catch{return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='GET'&&id){
    try{
      const[rec]=await sql`SELECT * FROM records WHERE id=${id} AND module=${mod}`;
      if(!rec)return res.status(404).json({error:'Nao encontrado'});
      const actions=await sql`SELECT * FROM actions WHERE record_id=${id} ORDER BY created_at`;
      const sigs=await sql`SELECT * FROM signatures WHERE record_id=${rec.code} ORDER BY signed_at DESC`;
      return res.json({...rec,actions,signatures:sigs});
    }catch{return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='POST'){
    if(!isAdm&&!perms.includes(`${mod}.abrir`))return res.status(403).json({error:'Sem permissao para abrir registros neste modulo'});
    try{
      const{title,description,priority,data}=req.body||{};
      if(!title?.trim())return res.status(400).json({error:'Titulo obrigatorio'});
      const code=await nextCode(mod),status=steps[0];
      const[rec]=await sql`INSERT INTO records(code,module,title,description,status,priority,data,owner_id,owner_name,created_by)VALUES(${code},${mod},${title.trim()},${description||''},${status},${priority||'media'},${JSON.stringify(data||{})}::jsonb,${d.id},${d.name},${d.id})RETURNING id,code,module,title,description,status,priority,owner_name,created_at`;
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},${mod},${'Aberto: '+code},${title})`;
      return res.status(201).json(rec);
    }catch{return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='PUT'&&id){
    try{
      const[ex]=await sql`SELECT * FROM records WHERE id=${id} AND module=${mod}`;
      if(!ex)return res.status(404).json({error:'Nao encontrado'});
      const{status,data,title,description,priority}=req.body||{};
      if(status&&status!==ex.status){
        if(steps.indexOf(status)===-1)return res.status(400).json({error:'Status invalido'});
        const np=steps.indexOf(status)>=steps.length-1?`${mod}.fechar`:`${mod}.analisar`;
        if(!isAdm&&!perms.includes(np))return res.status(403).json({error:'Sem permissao para esta transicao'});
      }
      await sql`UPDATE records SET status=${status||ex.status},title=${title||ex.title},description=${description??ex.description},priority=${priority||ex.priority},data=${JSON.stringify(data||ex.data)}::jsonb,updated_at=now() WHERE id=${id}`;
      if(status&&status!==ex.status)await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},${mod},${'Status: '+ex.status+' → '+status},${ex.code})`;
      return res.json({ok:true});
    }catch{return res.status(500).json({error:'Erro interno'});}
  }
  if(req.method==='DELETE'&&id){
    if(!isAdm&&!perms.includes(`${mod}.excluir`))return res.status(403).json({error:'Sem permissao'});
    try{
      const[ex]=await sql`SELECT code FROM records WHERE id=${id}`;
      if(!ex)return res.status(404).json({error:'Nao encontrado'});
      await sql`DELETE FROM actions WHERE record_id=${id}`;
      await sql`DELETE FROM records WHERE id=${id}`;
      await sql`INSERT INTO syslog(by,type,event,detail)VALUES(${d.name},${mod},'Excluido',${ex.code})`;
      return res.json({ok:true});
    }catch{return res.status(500).json({error:'Erro interno'});}
  }
  return res.status(405).json({error:'Method not allowed'});
};
