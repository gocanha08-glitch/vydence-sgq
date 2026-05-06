const ALL_PERMISSIONS = [
  'dashboard',
  'usuarios.gerenciar',
  'usuarios.importar',
  'grupos.ver',
  'grupos.gerenciar',
  'auditoria.ver',
  // RO
  'ro.abrir', 'ro.analisar', 'ro.aprovar', 'ro.fechar', 'ro.excluir',
  // NC
  'nc.abrir', 'nc.analisar', 'nc.aprovar', 'nc.fechar', 'nc.excluir',
  // RIACP
  'riacp.abrir', 'riacp.analisar', 'riacp.aprovar', 'riacp.fechar', 'riacp.excluir',
  // SA - Controle de Mudanças
  'sa.abrir', 'sa.analisar', 'sa.aprovar', 'sa.fechar', 'sa.excluir',
];

function hasPermission(permissions, perm) {
  return Array.isArray(permissions) && permissions.includes(perm);
}

async function getUserPermissions(sql, userId) {
  const rows = await sql`
    SELECT DISTINCT jsonb_array_elements_text(r.permissions) as perm
    FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ${userId}
  `;
  return rows.map(r => r.perm);
}

module.exports = { ALL_PERMISSIONS, hasPermission, getUserPermissions };
