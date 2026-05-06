const { sql } = require('../../lib/db');
const { requireAuth } = require('../../lib/auth');
const { cors } = require('../../lib/cors');
const { hasPermission } = require('../../lib/permissions');

const MODULE_STATUS = {
  ro:    ['Aberto','Em Análise','Aprovado','Fechado'],
  nc:    ['Aberto','Em Análise','Plano de Ação','Aprovado','Fechado'],
  riacp: ['Identificação','Análise de Causa','Plano de Ação','Verificação','Encerrado'],
  sa:    ['Solicitado','Avaliação','Aprovado','Implementação','Verificação','Encerrado'],
};

async function nextCode(module) {
  const year = new Date().getFullYear();
  const prefix = module.toUpperCase();
  await sql`
    INSERT INTO sequences (module, year, last) VALUES (${module}, ${year}, 0)
    ON CONFLICT (module, year) DO NOTHING
  `;
  const [row] = await sql`
    UPDATE sequences SET last = last + 1
    WHERE module = ${module} AND year = ${year}
    RETURNING last
  `;
  return `${prefix}-${String(row.last).padStart(3,'0')}/${year}`;
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = requireAuth(req, res); if (!decoded) return;
  const { module, id } = req.query || {};

  if (!module || !MODULE_STATUS[module]) return res.status(400).json({ error: 'Modulo invalido' });

  // GET — listar registros do módulo
  if (req.method === 'GET' && !id) {
    try {
      const rows = await sql`
        SELECT r.id, r.code, r.module, r.title, r.description, r.status, r.priority,
               r.data, r.owner_name, r.created_at, r.updated_at,
               u.name as creator_name
        FROM records r LEFT JOIN users u ON u.id = r.created_by
        WHERE r.module = ${module}
        ORDER BY r.created_at DESC
      `;
      return res.json(rows);
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // GET — buscar registro por ID
  if (req.method === 'GET' && id) {
    try {
      const [record] = await sql`SELECT * FROM records WHERE id = ${id} AND module = ${module}`;
      if (!record) return res.status(404).json({ error: 'Registro nao encontrado' });
      const actions = await sql`SELECT * FROM actions WHERE record_id = ${id} ORDER BY created_at`;
      const signatures = await sql`SELECT * FROM signatures WHERE record_id = ${record.code} ORDER BY signed_at DESC`;
      return res.json({ ...record, actions, signatures });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // POST — criar registro
  if (req.method === 'POST') {
    if (!hasPermission(decoded.permissions || [], `${module}.abrir`)) {
      return res.status(403).json({ error: 'Sem permissao para abrir registros neste modulo' });
    }
    try {
      const { title, description, priority, data } = req.body || {};
      if (!title?.trim()) return res.status(400).json({ error: 'Titulo obrigatorio' });

      const code    = await nextCode(module);
      const status  = MODULE_STATUS[module][0];
      const [record] = await sql`
        INSERT INTO records (code, module, title, description, status, priority, data, owner_id, owner_name, created_by)
        VALUES (${code}, ${module}, ${title.trim()}, ${description||''}, ${status},
                ${priority||'media'}, ${JSON.stringify(data||{})}::jsonb,
                ${decoded.id}, ${decoded.name}, ${decoded.id})
        RETURNING id, code, module, title, description, status, priority, owner_name, created_at
      `;
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, ${'criacao'}, ${'Registro aberto: ' + code}, ${title})`;
      return res.status(201).json(record);
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // PUT — atualizar status/dados
  if (req.method === 'PUT' && id) {
    try {
      const { status, data, title, description, priority, owner_id } = req.body || {};
      const [existing] = await sql`SELECT * FROM records WHERE id = ${id} AND module = ${module}`;
      if (!existing) return res.status(404).json({ error: 'Registro nao encontrado' });

      // Verificar permissão de avanço de status
      if (status && status !== existing.status) {
        const steps = MODULE_STATUS[module];
        const curIdx = steps.indexOf(existing.status);
        const newIdx = steps.indexOf(status);
        if (newIdx === -1) return res.status(400).json({ error: 'Status invalido' });
        // Requer permissão do status de destino
        const actionPerm = newIdx >= steps.length - 1 ? `${module}.fechar` : `${module}.analisar`;
        if (!decoded.role || (!['admin','sgq'].includes(decoded.role) && !hasPermission(decoded.permissions||[], actionPerm))) {
          return res.status(403).json({ error: 'Sem permissao para esta transicao' });
        }
      }

      await sql`
        UPDATE records SET
          status      = ${status || existing.status},
          title       = ${title || existing.title},
          description = ${description ?? existing.description},
          priority    = ${priority || existing.priority},
          data        = ${JSON.stringify(data || existing.data)}::jsonb,
          owner_id    = ${owner_id || existing.owner_id},
          updated_at  = now()
        WHERE id = ${id}
      `;

      if (status && status !== existing.status) {
        await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, ${module}, ${'Status: ' + existing.status + ' → ' + status}, ${existing.code})`;
      }
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  // DELETE — excluir (admin only)
  if (req.method === 'DELETE' && id) {
    if (!['admin','sgq'].includes(decoded.role) && !hasPermission(decoded.permissions||[], `${module}.excluir`)) {
      return res.status(403).json({ error: 'Sem permissao' });
    }
    try {
      const [existing] = await sql`SELECT code FROM records WHERE id = ${id}`;
      if (!existing) return res.status(404).json({ error: 'Registro nao encontrado' });
      await sql`DELETE FROM actions WHERE record_id = ${id}`;
      await sql`DELETE FROM records WHERE id = ${id}`;
      await sql`INSERT INTO syslog (by, type, event, detail) VALUES (${decoded.name}, ${module}, 'Registro excluido', ${existing.code})`;
      return res.json({ ok: true });
    } catch (err) { return res.status(500).json({ error: 'Erro interno' }); }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
