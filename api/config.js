const jwt = require('jsonwebtoken');
const { sql } = require('../lib/db');
const { cors } = require('../lib/cors');

const SECRET = process.env.JWT_SECRET||'dev-secret';
function verifyToken(req){const a=req.headers.authorization||'';const t=a.startsWith('Bearer ')?a.slice(7):null;if(!t)return null;try{return jwt.verify(t,SECRET);}catch{return null;}}
function requireAuth(req,res){const u=verifyToken(req);if(!u){res.status(401).json({error:'Nao autenticado'});return null;}return u;}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = requireAuth(req,res); if(!decoded) return;
  const key = req.query.key;
  if (!key) return res.status(400).json({error:'Chave obrigatoria'});

  if (req.method === 'GET') {
    try {
      if (key === 'syslog') {
        const rows = await sql`SELECT id,at,by,type,event,detail FROM syslog ORDER BY at DESC LIMIT 200`;
        return res.json(rows);
      }
      const rows = await sql`SELECT value FROM config WHERE key=${key} LIMIT 1`;
      return res.json(rows[0]?rows[0].value:null);
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  if (req.method === 'PUT') {
    try {
      const {value} = req.body||{};
      if (key === 'syslog') {
        const entries = Array.isArray(value)?value:[value];
        for (const e of entries)
          await sql`INSERT INTO syslog(at,by,type,event,detail) VALUES(${e.at||new Date().toISOString()},${e.by||''},${e.type||'sistema'},${e.event||''},${e.detail||''})`;
        return res.json({ok:true});
      }
      await sql`INSERT INTO config(key,value,updated_at,updated_by) VALUES(${key},${JSON.stringify(value)}::jsonb,now(),${decoded.name}) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now(),updated_by=EXCLUDED.updated_by`;
      return res.json({ok:true});
    } catch { return res.status(500).json({error:'Erro interno'}); }
  }

  return res.status(405).json({error:'Method not allowed'});
};
