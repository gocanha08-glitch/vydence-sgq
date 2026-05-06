const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'dev-secret-trocar-em-producao';

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name,
      permissions: user.permissions || [], groups: user.groups || [], area: user.area || '' },
    SECRET,
    { expiresIn: '8h' }
  );
}

function verifyToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  try { return jwt.verify(token, SECRET); }
  catch { return null; }
}

function requireAuth(req, res) {
  const user = verifyToken(req);
  if (!user) { res.status(401).json({ error: 'Nao autenticado' }); return null; }
  return user;
}

function requireAdmin(req, res) {
  const user = verifyToken(req);
  if (!user) { res.status(401).json({ error: 'Nao autenticado' }); return null; }
  if (!['admin', 'sgq'].includes(user.role)) {
    res.status(403).json({ error: 'Sem permissao' }); return null;
  }
  return user;
}

module.exports = { signToken, verifyToken, requireAuth, requireAdmin };
