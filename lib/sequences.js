const { sql } = require('./db');
async function nextSequence(module) {
  const year = new Date().getFullYear();
  const prefix = module.toUpperCase();
  const rows = await sql`
    INSERT INTO sequences (module, year, last_seq) VALUES (${prefix}, ${year}, 1)
    ON CONFLICT (module, year) DO UPDATE SET last_seq = sequences.last_seq + 1
    RETURNING last_seq
  `;
  const seq = rows[0].last_seq;
  return `${prefix}-${String(seq).padStart(3,'0')}/${year}`;
}
module.exports = { nextSequence };