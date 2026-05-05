const crypto = require('crypto');
const { sql } = require('./db');
async function saveSignature(req, { recordId, module, userId, userName, action, detail, meaning }) {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '';
    const ua = req.headers['user-agent'] || '';
    const payload = `${module}|${recordId}|${userId}|${action}|${new Date().toISOString()}`;
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    await sql`
      INSERT INTO signatures (record_id, module, user_id, user_name, action, detail, meaning, hash, ip_address, user_agent, signed_at)
      VALUES (${recordId}, ${module}, ${parseInt(userId)}, ${userName}, ${action}, ${detail||''}, ${meaning||''}, ${hash}, ${ip}, ${ua}, now())
    `;
    return hash;
  } catch(err) { console.error('[signature]', err.message); return null; }
}
module.exports = { saveSignature };