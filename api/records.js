// api/records.js — módulo unificado para RO, NC, RIACP, SA
// Para o módulo SA: compatível com o formato do Change Management
// (salva objeto completo em data JSONB, devolve expandido para o frontend)

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

const ra = (req, res) => {
  const u = vt(req);
  if (!u) { res.status(401).json({ error: 'Nao autenticado' }); return null; }
  return u;
};

const nextCode = async mod => {
  const y = new Date().getFullYear();
  const prefix = {sa:'SA',ro:'RO',nc:'NC',riacp:'RIACP'}[mod] || mod.toUpperCase();
  await sql`INSERT INTO sequences(module,year,last) VALUES(${mod},${y},0) ON CONFLICT(module,year) DO NOTHING`;
  const [r] = await sql`UPDATE sequences SET last=last+1 WHERE module=${mod} AND year=${y} RETURNING last`;
  return `${prefix}-${String(r.last).padStart(3,'0')}/${y}`;
};

module.exports = async (req, res) => {
  CORS(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const user = ra(req, res);
  if (!user) return;

  const { module: mod, id } = req.query || {};
  if (!mod || !['ro','nc','riacp','sa'].includes(mod)) {
    return res.status(400).json({ error: 'Modulo invalido. Use: ro, nc, riacp ou sa' });
  }

  // Helper: verifica se o usuário tem uma permissão específica via grupos (ou é admin)
  const userHasPerm = async (perm) => {
    if (user.role === 'admin') return true;
    try {
      const rows = await sql`SELECT r.permissions FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=${user.id}`;
      for (const x of rows) {
        const p = Array.isArray(x.permissions) ? x.permissions : [];
        if (p.includes(perm)) return true;
      }
    } catch (e) {}
    return false;
  };

  // ── GET lista ────────────────────────────────────────────────
  if (req.method === 'GET' && !id) {
    try {
      const rows = await sql`
        SELECT id, code, module, title, status, data, created_at, updated_at
        FROM records
        WHERE module = ${mod}
        ORDER BY created_at DESC
      `;

      // Para todos os módulos: devolve objeto data expandido
      // data contém o objeto completo salvo pelo frontend
      return res.json(rows.map(r => ({
        ...( r.data || {} ),
        _db_id: r.id,
        id: (r.data && (r.data.id || r.data.code)) || r.code,
        code: r.code,
        status: r.status,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      })));
    } catch (err) {
      console.error('GET records error:', err);
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  // ── GET por id ───────────────────────────────────────────────
  if (req.method === 'GET' && id) {
    try {
      const [rec] = await sql`
        SELECT * FROM records WHERE code = ${id} AND module = ${mod}
      `;
      if (!rec) return res.status(404).json({ error: 'Nao encontrado' });

      if (mod === 'sa') {
        return res.json({
          ...( rec.data || {} ),
          _db_id: rec.id,
          id: (rec.data && rec.data.id) || rec.code,
          code: rec.code,
        });
      }

      return res.json({
        ...( rec.data || {} ),
        _db_id: rec.id,
        id: (rec.data && (rec.data.id || rec.data.code)) || rec.code,
        code: rec.code,
        status: rec.status,
        createdAt: rec.created_at,
        updatedAt: rec.updated_at,
      });
    } catch (err) {
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  // ── POST criar ───────────────────────────────────────────────
  if (req.method === 'POST') {
    try {
      if (mod === 'sa') {
        // Recebe o objeto SA completo do frontend CM
        const sa = req.body || {};
        if (!sa.title || !sa.title.trim()) {
          return res.status(400).json({ error: 'Titulo obrigatorio' });
        }

        // Gera código se não veio do frontend
        const code = sa.id || await nextCode(mod);
        sa.id = code; // garante que o id dentro do data é o code

        await sql`
          INSERT INTO records (code, module, title, description, status, priority, data, owner_id, owner_name, created_by)
          VALUES (
            ${code},
            'sa',
            ${sa.title.trim()},
            ${sa.description || ''},
            ${sa.status || 'aberta'},
            'media',
            ${JSON.stringify(sa)}::jsonb,
            ${user.id},
            ${user.name},
            ${user.id}
          )
          ON CONFLICT (code) DO UPDATE SET
            data = ${JSON.stringify(sa)}::jsonb,
            status = ${sa.status || 'aberta'},
            updated_at = now()
        `;

        await sql`
          INSERT INTO syslog (by, type, event, detail)
          VALUES (${user.name}, 'sa', ${'SA criada: ' + code}, ${sa.title})
        `;

        return res.status(201).json({ ok: true, id: code, code });
      }

      // Outros módulos (RO, NC, RIACP) — salva objeto completo em data (mesmo padrão SA)
      const body = req.body || {};
      const title = (body.title || (body.data && body.data.descricao && body.data.descricao.substring(0,80)) || 'Sem titulo').trim();
      const code = await nextCode(mod);
      body.code = code;
      body.id = code;

      await sql`
        INSERT INTO records (code, module, title, description, status, priority, data, owner_id, owner_name, created_by)
        VALUES (
          ${code}, ${mod},
          ${title},
          ${(body.data && body.data.descricao) || ''},
          ${body.status || 'aberta'},
          'media',
          ${JSON.stringify(body)}::jsonb,
          ${user.id}, ${user.name}, ${user.id}
        )
      `;

      await sql`
        INSERT INTO syslog (by, type, event, detail)
        VALUES (${user.name}, ${mod}, ${mod.toUpperCase() + ' criada: ' + code}, ${title})
      `;

      return res.status(201).json({ ok: true, id: code, code });
    } catch (err) {
      console.error('POST records error:', err);
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  // ── PUT atualizar ────────────────────────────────────────────
  if (req.method === 'PUT' && id) {
    try {
      if (mod === 'sa') {
        // Recebe o objeto SA completo e salva tudo
        const sa = req.body || {};
        const saId = sa.id || id;

        // Tenta buscar por code (SA-001/2025)
        const [ex] = await sql`SELECT id FROM records WHERE code = ${saId} AND module = 'sa'`;

        if (ex) {
          await sql`
            UPDATE records SET
              title = ${sa.title || ''},
              description = ${sa.description || ''},
              status = ${sa.status || 'aberta'},
              data = ${JSON.stringify(sa)}::jsonb,
              updated_at = now()
            WHERE code = ${saId} AND module = 'sa'
          `;
        } else {
          // Não existe — cria (upsert)
          await sql`
            INSERT INTO records (code, module, title, description, status, priority, data, owner_id, owner_name, created_by)
            VALUES (
              ${saId}, 'sa',
              ${sa.title || ''},
              ${sa.description || ''},
              ${sa.status || 'aberta'},
              'media',
              ${JSON.stringify(sa)}::jsonb,
              ${user.id}, ${user.name}, ${user.id}
            )
          `;
        }

        return res.json({ ok: true });
      }

      // Outros módulos (RO, NC, RIACP) — mesmo padrão SA, salva objeto completo
      const body = req.body || {};
      const roId = body.id || body.code || id;
      const [ex] = await sql`SELECT id FROM records WHERE code = ${roId} AND module = ${mod}`;

      if (ex) {
        const titleUpd = (body.title || (body.data && body.data.descricao && body.data.descricao.substring(0,80)) || '').trim();
        await sql`
          UPDATE records SET
            title      = CASE WHEN ${titleUpd} != '' THEN ${titleUpd} ELSE title END,
            description = ${(body.data && body.data.descricao) || ''},
            status     = ${body.status || 'aberta'},
            data       = ${JSON.stringify(body)}::jsonb,
            updated_at = now()
          WHERE code = ${roId} AND module = ${mod}
        `;
      } else {
        return res.status(404).json({ error: 'Registro nao encontrado: ' + roId });
      }
      return res.json({ ok: true });
    } catch (err) {
      console.error('PUT records error:', err);
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  // ── DELETE ───────────────────────────────────────────────────
  if (req.method === 'DELETE' && id) {
    const canDel = await userHasPerm(mod + '.excluir');
    if (!canDel) return res.status(403).json({ error: 'Sem permissao' });
    try {
      await sql`DELETE FROM records WHERE code = ${id} AND module = ${mod}`;
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
