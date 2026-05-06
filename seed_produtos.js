// seed_produtos.js — roda uma vez para popular a tabela produtos no Neon
// node seed_produtos.js

require('dotenv').config();
const { neon } = require('@neondatabase/serverless');

const DATABASE_URL = process.env.DATABASE_URL || '';
if (!DATABASE_URL) { console.error('DATABASE_URL não definido'); process.exit(1); }

const sql = neon(DATABASE_URL);

const produtos = [
  { codigo: "026377", descricao: "KIT COMPLETO PLACA MODELO LM-PW1-001 - PEME V1.1 - R1.0 – RETRAB MS-PW1-001", tipo: "TP", unidade: "UN", familia: "Placa PW1" },
  { codigo: "025358", descricao: "KIT COMPLETO PLACA MODELO LM-PW1-001 - PEME V1.1 - R1.3 ROHS", tipo: "PI", unidade: "UN", familia: "Placa PW1" },
  { codigo: "026438", descricao: "KIT COMPLETO PLACA MODELO LM-PW1-001 - PEME V1.2 - R1.0 ROHS", tipo: "MP", unidade: "UN", familia: "Placa PW1" },
  { codigo: "029897", descricao: "KIT COMPLETO PLACA MODELO LM-PW1-001 - PEME V1.2 - R1.0 ROHS - RETRAB MS-PW1-003", tipo: "MP", unidade: "UN", familia: "Placa PW1" },
  { codigo: "029932", descricao: "KIT COMPLETO PLACA MODELO LM-PW1-001 - PEME V1.2 - R1.1 ROHS", tipo: "MP", unidade: "UN", familia: "Placa PW1" },
  { codigo: "020424", descricao: "KIT PLACA DE CI PW1-001-PEME V1.1", tipo: "PI", unidade: "UN", familia: "Placa PW1" },
  { codigo: "025385", descricao: "KIT PLACA LM-PW1-001 - PEME V1.1 - R1.1 RETRAB MS-PW1-001", tipo: "PI", unidade: "UN", familia: "Placa PW1" },
];

async function seed() {
  await sql`
    CREATE TABLE IF NOT EXISTS produtos (
      codigo      VARCHAR(100) PRIMARY KEY,
      descricao   TEXT         NOT NULL,
      tipo        VARCHAR(20),
      unidade     VARCHAR(20)  DEFAULT 'UN',
      familia     VARCHAR(100),
      ativo       BOOLEAN      DEFAULT true,
      updated_at  TIMESTAMPTZ  DEFAULT now(),
      updated_by  VARCHAR(200)
    )
  `;
  console.log('Tabela garantida.');

  let ins = 0, upd = 0;
  for (const p of produtos) {
    const ex = await sql`SELECT 1 FROM produtos WHERE codigo = ${p.codigo}`;
    if (ex.length) {
      await sql`UPDATE produtos SET descricao=${p.descricao}, tipo=${p.tipo}, unidade=${p.unidade}, familia=${p.familia}, ativo=true, updated_at=now(), updated_by='seed' WHERE codigo=${p.codigo}`;
      upd++;
    } else {
      await sql`INSERT INTO produtos (codigo,descricao,tipo,unidade,familia,ativo,updated_by) VALUES (${p.codigo},${p.descricao},${p.tipo},${p.unidade},${p.familia},true,'seed')`;
      ins++;
    }
  }
  console.log(`Seed concluído: ${ins} inseridos, ${upd} atualizados.`);
  process.exit(0);
}

seed().catch(e => { console.error(e); process.exit(1); });
