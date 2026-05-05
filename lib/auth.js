const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'sgq-secret-2024';
function requireAuth(req, res) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) { res.status(401).json({ error: 'Nao autenticado' }); return null; }
  try { return jwt.verify(token, SECRET); }
  catch { res.status(401).json({ error: 'Token invalido' }); return null; }
}
function signToken(user) {
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email, permissions: user.permissions || [], isAdmin: user.is_admin || false },
    SECRET, { expiresIn: '12h' }
  );
}
module.exports = { requireAuth, signToken };