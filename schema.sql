-- ================================================================
-- SCHEMA — SGQ Vydence Medical
-- Execute no SQL Editor do Neon para inicializar o banco
-- ================================================================

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  email           TEXT UNIQUE NOT NULL,
  area            TEXT DEFAULT '',
  role            TEXT NOT NULL DEFAULT 'geral',  -- admin | sgq | geral
  pwd_hash        TEXT NOT NULL,
  pwd_hash_prev   TEXT,
  eval_depts      JSONB DEFAULT '[]',
  active          BOOLEAN DEFAULT true,
  reset_token     TEXT,
  reset_expires   TIMESTAMPTZ,
  login_attempts  INT DEFAULT 0,
  locked_until    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now(),
  created_by      TEXT DEFAULT ''
);

-- ROLES (grupos de permissão)
CREATE TABLE IF NOT EXISTS roles (
  id          SERIAL PRIMARY KEY,
  name        TEXT UNIQUE NOT NULL,
  description TEXT,
  permissions JSONB DEFAULT '[]',
  is_system   BOOLEAN DEFAULT false,
  created_at  TIMESTAMPTZ DEFAULT now(),
  created_by  TEXT DEFAULT ''
);

-- USER_ROLES (N:N)
CREATE TABLE IF NOT EXISTS user_roles (
  user_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role_id  INTEGER REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- SYSLOG (auditoria)
CREATE TABLE IF NOT EXISTS syslog (
  id      SERIAL PRIMARY KEY,
  at      TIMESTAMPTZ DEFAULT now(),
  by      TEXT NOT NULL,
  type    TEXT NOT NULL,
  event   TEXT NOT NULL,
  detail  TEXT DEFAULT ''
);

-- CONFIG
CREATE TABLE IF NOT EXISTS config (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now(),
  updated_by TEXT DEFAULT ''
);

-- SIGNATURES (assinaturas digitais)
CREATE TABLE IF NOT EXISTS signatures (
  id            SERIAL PRIMARY KEY,
  record_id     TEXT,
  action        TEXT NOT NULL,
  action_detail TEXT,
  signed_by_id  INTEGER REFERENCES users(id),
  signed_by     TEXT NOT NULL,
  signed_at     TIMESTAMPTZ DEFAULT now(),
  ip_address    TEXT,
  user_agent    TEXT,
  meaning       TEXT,
  hash          TEXT
);

-- SEQUENCES (controle de numeração por módulo/ano)
CREATE TABLE IF NOT EXISTS sequences (
  module  TEXT NOT NULL,
  year    INT  NOT NULL,
  last    INT  DEFAULT 0,
  PRIMARY KEY (module, year)
);

-- RECORDS (registros dos módulos: RO, NC, RIACP, SA)
CREATE TABLE IF NOT EXISTS records (
  id          SERIAL PRIMARY KEY,
  code        TEXT UNIQUE NOT NULL,      -- ex: RO-001/2025
  module      TEXT NOT NULL,             -- ro | nc | riacp | sa
  title       TEXT NOT NULL,
  description TEXT DEFAULT '',
  status      TEXT NOT NULL,
  priority    TEXT DEFAULT 'media',      -- baixa | media | alta | critica
  data        JSONB DEFAULT '{}',        -- dados extras por módulo
  owner_id    INTEGER REFERENCES users(id),
  owner_name  TEXT DEFAULT '',
  created_by  INTEGER REFERENCES users(id),
  created_at  TIMESTAMPTZ DEFAULT now(),
  updated_at  TIMESTAMPTZ DEFAULT now()
);

-- ACTIONS (ações associadas a registros)
CREATE TABLE IF NOT EXISTS actions (
  id          SERIAL PRIMARY KEY,
  record_id   INTEGER REFERENCES records(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  responsible TEXT DEFAULT '',
  due_date    DATE,
  done        BOOLEAN DEFAULT false,
  done_at     TIMESTAMPTZ,
  created_by  TEXT DEFAULT '',
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- RECORD_LINKS (vínculos entre registros: RO→NC→RIACP)
CREATE TABLE IF NOT EXISTS record_links (
  parent_id  INTEGER REFERENCES records(id),
  child_id   INTEGER REFERENCES records(id),
  link_type  TEXT DEFAULT 'origin',
  PRIMARY KEY (parent_id, child_id)
);

-- ÍNDICES
CREATE INDEX IF NOT EXISTS idx_records_module  ON records(module);
CREATE INDEX IF NOT EXISTS idx_records_status  ON records(status);
CREATE INDEX IF NOT EXISTS idx_actions_record  ON actions(record_id);
CREATE INDEX IF NOT EXISTS idx_syslog_at       ON syslog(at DESC);

-- ================================================================
-- SEED: roles do sistema
-- ================================================================
INSERT INTO roles (name, description, permissions, is_system) VALUES
('Administradores', 'Acesso total ao sistema', '["dashboard","usuarios.gerenciar","grupos.gerenciar","auditoria.ver","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar"]'::jsonb, true),
('SGQ', 'Equipe de Qualidade', '["dashboard","auditoria.ver","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar"]'::jsonb, true),
('Geral', 'Usuário padrão', '["dashboard","ro.abrir","nc.abrir","sa.abrir"]'::jsonb, true)
ON CONFLICT (name) DO NOTHING;

-- ================================================================
-- SEED: admin inicial (senha: Admin@123)
-- Use /api/setup para criar com hash real
-- ================================================================
-- Placeholder — rodar /api/setup após deploy
