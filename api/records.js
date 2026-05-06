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
  await sql`INSERT INTO sequences(module,year,last) VALUES(${mod},${y},0) ON CONFLICT(module,year) DO NOTHING`;
  const [r] = await sql`UPDATE sequences SET last=last+1 WHERE module=${mod} AND year=${y} RETURNING last`;
  return `SA-${String(r.last).padStart(3,'0')}/${y}`;
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

  const isAdm = ['admin','sgq'].includes(user.role);

  // ── GET lista ────────────────────────────────────────────────
  if (req.method === 'GET' && !id) {
    try {
      const rows = await sql`
        SELECT id, code, module, title, status, data, created_at, updated_at
        FROM records
        WHERE module = ${mod}
        ORDER BY created_at DESC
      `;

      if (mod === 'sa') {
        // Para SA: devolve o objeto data expandido (formato CM)
        // data já contém o objeto SA completo salvo pelo frontend
        return res.json(rows.map(r => ({
          ...( r.data || {} ),
          _db_id: r.id,
          id: (r.data && r.data.id) || r.code,
          code: r.code,
        })));
      }

      return res.json(rows);
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

      return res.json(rec);
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

      // Outros módulos (RO, NC, RIACP) — formato padrão
      const { title, description, priority, data } = req.body || {};
      if (!title?.trim()) return res.status(400).json({ error: 'Titulo obrigatorio' });
      const code = await nextCode(mod);
      const [rec] = await sql`
        INSERT INTO records (code, module, title, description, status, priority, data, owner_id, owner_name, created_by)
        VALUES (${code}, ${mod}, ${title.trim()}, ${description||''}, 'aberto', ${priority||'media'}, ${JSON.stringify(data||{})}::jsonb, ${user.id}, ${user.name}, ${user.id})
        RETURNING id, code, module, title, status, created_at
      `;
      return res.status(201).json(rec);
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

      // Outros módulos
      const [ex] = await sql`SELECT * FROM records WHERE id = ${id} AND module = ${mod}`;
      if (!ex) return res.status(404).json({ error: 'Nao encontrado' });
      const { status, data, title, description, priority } = req.body || {};
      await sql`
        UPDATE records SET
          status = ${status || ex.status},
          title = ${title || ex.title},
          description = ${description ?? ex.description},
          priority = ${priority || ex.priority},
          data = ${JSON.stringify(data || ex.data)}::jsonb,
          updated_at = now()
        WHERE id = ${id}
      `;
      return res.json({ ok: true });
    } catch (err) {
      console.error('PUT records error:', err);
      return res.status(500).json({ error: 'Erro interno', detail: err.message });
    }
  }

  // ── DELETE ───────────────────────────────────────────────────
  if (req.method === 'DELETE' && id) {
    if (!isAdm) return res.status(403).json({ error: 'Sem permissao' });
    try {
      await sql`DELETE FROM records WHERE code = ${id} AND module = ${mod}`;
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: 'Erro interno' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
