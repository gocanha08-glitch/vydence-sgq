// api/produtos.js — cadastro de produtos para todos os módulos
const jwt = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');
const sql = neon(process.env.DATABASE_URL);
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const CORS = res => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
};

const vt = req => {
  const a = req.headers.authorization || '';
  const t = a.startsWith('Bearer ') ? a.slice(7) : null;
  if (!t) return null;
  try { return jwt.verify(t, SECRET); } catch { return null; }
};

// Garante que a tabela existe
const ensureTable = async () => {
  await sql`
    CREATE TABLE IF NOT EXISTS produtos (
      codigo      VARCHAR(50)  PRIMARY KEY,
      descricao   TEXT         NOT NULL,
      tipo        VARCHAR(20),
      unidade     VARCHAR(20)  DEFAULT 'UN',
      familia     VARCHAR(100),
      ativo       BOOLEAN      DEFAULT true,
      updated_at  TIMESTAMPTZ  DEFAULT now(),
      updated_by  VARCHAR(100)
    )
  `;
};

module.exports = async (req, res) => {
  CORS(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const user = vt(req);
  if (!user) return res.status(401).json({ error: 'Nao autenticado' });

  // Verifica se o usuário tem a permissão produtos.gerenciar (via grupos) ou é admin
  let isAdm = user.role === 'admin';
  if (!isAdm) {
    try {
      const rows = await sql`SELECT r.permissions FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=${user.id}`;
      for (const x of rows) {
        const p = Array.isArray(x.permissions) ? x.permissions : [];
        if (p.includes('produtos.gerenciar')) { isAdm = true; break; }
      }
    } catch (e) {}
  }

  await ensureTable();

  // ── GET busca ────────────────────────────────────────────────
  // ?q=termo  → busca por código ou descrição (autocomplete)
  // ?codigo=X → busca exata por código
  if (req.method === 'GET') {
    try {
      const { q, codigo } = req.query || {};

      if (codigo) {
        const rows = await sql`
          SELECT codigo, descricao, tipo, unidade, familia
          FROM produtos
          WHERE LOWER(codigo) = LOWER(${codigo}) AND ativo = true
          LIMIT 1
        `;
        return res.json(rows[0] || null);
      }

      if (q && q.trim()) {
        const termo = '%' + q.trim().toLowerCase() + '%';
        const rows = await sql`
          SELECT codigo, descricao, tipo, unidade, familia
          FROM produtos
          WHERE ativo = true
            AND (LOWER(codigo) LIKE ${termo} OR LOWER(descricao) LIKE ${termo})
          ORDER BY codigo
          LIMIT 20
        `;
        return res.json(rows);
      }

      // Sem filtro — devolve todos (tela de administração)
      const rows = await sql`
        SELECT codigo, descricao, tipo, unidade, familia, ativo, updated_at, updated_by
        FROM produtos
        ORDER BY codigo
      `;
      return res.json(rows);
    } catch (err) {
      console.error('GET produtos error:', err);
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  // ── POST — inserir ou upsert em lote (sync/upload) ───────────
  if (req.method === 'POST') {
    if (!isAdm) return res.status(403).json({ error: 'Sem permissao' });
    try {
      const body = req.body || {};

      // Lote: { produtos: [...], replace: true/false }
      if (Array.isArray(body.produtos)) {
        const { produtos, replace } = body;

        if (replace) {
          // Desativa todos antes de recarregar
          await sql`UPDATE produtos SET ativo = false`;
        }

        let inserted = 0, updated = 0;
        for (const p of produtos) {
          if (!p.codigo || !p.descricao) continue;
          const exists = await sql`SELECT 1 FROM produtos WHERE codigo = ${p.codigo}`;
          if (exists.length) {
            await sql`
              UPDATE produtos SET
                descricao  = ${p.descricao},
                tipo       = ${p.tipo || null},
                unidade    = ${p.unidade || 'UN'},
                familia    = ${p.familia || null},
                ativo      = true,
                updated_at = now(),
                updated_by = ${user.name}
              WHERE codigo = ${p.codigo}
            `;
            updated++;
          } else {
            await sql`
              INSERT INTO produtos (codigo, descricao, tipo, unidade, familia, ativo, updated_by)
              VALUES (${p.codigo}, ${p.descricao}, ${p.tipo||null}, ${p.unidade||'UN'}, ${p.familia||null}, true, ${user.name})
            `;
            inserted++;
          }
        }

        await sql`
          INSERT INTO syslog (by, type, event, detail)
          VALUES (${user.name}, 'produtos', 'Sync de produtos', ${`${inserted} inseridos, ${updated} atualizados`})
        `;

        return res.json({ ok: true, inserted, updated, total: produtos.length });
      }

      // Produto único
      const { codigo, descricao, tipo, unidade, familia } = body;
      if (!codigo || !descricao) return res.status(400).json({ error: 'codigo e descricao obrigatorios' });

      await sql`
        INSERT INTO produtos (codigo, descricao, tipo, unidade, familia, updated_by)
        VALUES (${codigo}, ${descricao}, ${tipo||null}, ${unidade||'UN'}, ${familia||null}, ${user.name})
        ON CONFLICT (codigo) DO UPDATE SET
          descricao  = ${descricao},
          tipo       = ${tipo||null},
          unidade    = ${unidade||'UN'},
          familia    = ${familia||null},
          ativo      = true,
          updated_at = now(),
          updated_by = ${user.name}
      `;
      return res.status(201).json({ ok: true });
    } catch (err) {
      console.error('POST produtos error:', err);
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  // ── PUT — editar produto individual ─────────────────────────
  if (req.method === 'PUT') {
    if (!isAdm) return res.status(403).json({ error: 'Sem permissao' });
    try {
      const { codigo } = req.query || {};
      const { descricao, tipo, unidade, familia, ativo } = req.body || {};
      if (!codigo) return res.status(400).json({ error: 'codigo obrigatorio' });
      await sql`
        UPDATE produtos SET
          descricao  = COALESCE(${descricao||null}, descricao),
          tipo       = COALESCE(${tipo||null}, tipo),
          unidade    = COALESCE(${unidade||null}, unidade),
          familia    = COALESCE(${familia||null}, familia),
          ativo      = COALESCE(${ativo!=null?ativo:null}, ativo),
          updated_at = now(),
          updated_by = ${user.name}
        WHERE codigo = ${codigo}
      `;
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  // ── DELETE — desativa (soft delete) ─────────────────────────
  if (req.method === 'DELETE') {
    if (!isAdm) return res.status(403).json({ error: 'Sem permissao' });
    try {
      const { codigo } = req.query || {};
      if (!codigo) return res.status(400).json({ error: 'codigo obrigatorio' });
      await sql`UPDATE produtos SET ativo = false WHERE codigo = ${codigo}`;
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
