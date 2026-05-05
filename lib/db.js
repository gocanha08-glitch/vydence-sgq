const { neon } = require('@neondatabase/serverless');
let _sql;
function getSQL() {
  if (!_sql) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL nao configurada');
    _sql = neon(process.env.DATABASE_URL);
  }
  return _sql;
}
module.exports = { get sql() { return getSQL(); } };