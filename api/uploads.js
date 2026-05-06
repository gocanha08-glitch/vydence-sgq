// api/uploads.js — upload de arquivos via Cloudflare R2 (URLs pré-assinadas)
const jwt = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');
const sql = neon(process.env.DATABASE_URL);
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const CORS = res => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
};

const vt = req => {
  const a = req.headers.authorization || '';
  const t = a.startsWith('Bearer ') ? a.slice(7) : null;
  if (!t) return null;
  try { return jwt.verify(t, SECRET); } catch { return null; }
};

// Gera URL pré-assinada manualmente (sem SDK pesado)
// Compatível com S3/R2 usando crypto nativo do Node
const crypto = require('crypto');

function signR2(method, bucket, key, endpoint, accessKey, secretKey, expiresIn = 300) {
  const url = new URL(`${endpoint}/${bucket}/${key}`);
  const datetime = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const date = datetime.slice(0, 8);
  const region = 'auto';
  const service = 's3';

  const credentialScope = `${date}/${region}/${service}/aws4_request`;
  const credential = `${accessKey}/${credentialScope}`;

  const queryParams = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': datetime,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': 'host',
  });

  // Sort params
  const sortedQuery = Array.from(queryParams.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  const canonicalRequest = [
    method,
    `/${bucket}/${key}`,
    sortedQuery,
    `host:${url.hostname}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    datetime,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretKey}`, date), region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return `${url.origin}/${bucket}/${key}?${sortedQuery}&X-Amz-Signature=${signature}`;
}

module.exports = async (req, res) => {
  CORS(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const user = vt(req);
  if (!user) return res.status(401).json({ error: 'Nao autenticado' });

  const R2_ENDPOINT      = process.env.R2_ENDPOINT;
  const R2_BUCKET        = process.env.R2_BUCKET;
  const R2_ACCESS_KEY    = process.env.R2_ACCESS_KEY_ID;
  const R2_SECRET_KEY    = process.env.R2_SECRET_ACCESS_KEY;

  // Se R2 não configurado ainda, retorna erro claro
  if (!R2_ENDPOINT || !R2_BUCKET || !R2_ACCESS_KEY || !R2_SECRET_KEY) {
    return res.status(503).json({
      error: 'Upload nao configurado. Configure as variaveis R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID e R2_SECRET_ACCESS_KEY no Vercel.'
    });
  }

  // POST — gerar URL de upload
  if (req.method === 'POST') {
    try {
      const { filename, contentType, refId, refType } = req.body || {};
      if (!filename) return res.status(400).json({ error: 'filename obrigatorio' });

      // Organiza por módulo/id/timestamp_filename
      const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
      const key = `${refType || 'misc'}/${refId || 'misc'}/${Date.now()}_${safe}`;

      const uploadUrl = signR2('PUT', R2_BUCKET, key, R2_ENDPOINT, R2_ACCESS_KEY, R2_SECRET_KEY, 300);

      return res.json({ uploadUrl, key });
    } catch (err) {
      console.error('Upload POST error:', err);
      return res.status(500).json({ error: 'Erro ao gerar URL de upload', detail: err.message });
    }
  }

  // GET — gerar URL de download
  if (req.method === 'GET') {
    try {
      const { key } = req.query || {};
      if (!key) return res.status(400).json({ error: 'key obrigatoria' });

      const downloadUrl = signR2('GET', R2_BUCKET, key, R2_ENDPOINT, R2_ACCESS_KEY, R2_SECRET_KEY, 3600);

      return res.json({ downloadUrl });
    } catch (err) {
      console.error('Upload GET error:', err);
      return res.status(500).json({ error: 'Erro ao gerar URL de download', detail: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
