const ALLOWED = ['https://vydence-sgq.vercel.app', process.env.APP_URL].filter(Boolean);
module.exports = function cors(req, res, methods = 'GET, POST, PUT, DELETE, OPTIONS') {
  const origin = req.headers.origin;
  if (origin && ALLOWED.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', methods);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
};