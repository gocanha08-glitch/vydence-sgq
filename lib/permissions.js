const PERMISSIONS = {
  'ro.abrir':'Abrir RO','ro.editar':'Editar RO','ro.decidir':'Decidir na RO',
  'ro.encerrar':'Encerrar RO','ro.cancelar':'Cancelar RO','ro.ver':'Ver ROs',
  'nc.abrir':'Abrir NC','nc.editar':'Editar NC','nc.analisar':'Analisar NC',
  'nc.disposicao':'Disposicao NC','nc.encerrar':'Encerrar NC','nc.cancelar':'Cancelar NC','nc.ver':'Ver NCs',
  'riacp.abrir':'Abrir RIACP','riacp.investigar':'Investigar','riacp.plano':'Plano Acoes',
  'riacp.eficacia':'Avaliar Eficacia','riacp.concluir':'Concluir RIACP','riacp.cancelar':'Cancelar RIACP','riacp.ver':'Ver RIACPs',
  'sa.abrir':'Abrir SA','sa.avaliacao_inicial':'Avaliacao Inicial','sa.concluir':'Concluir SA','sa.cancelar':'Cancelar SA','sa.ver':'Ver SAs',
  'admin.usuarios':'Gerenciar Usuarios','admin.grupos':'Gerenciar Grupos','auditoria.ver':'Ver Auditoria',
};
function hasPermission(permissions, perm) {
  if (!permissions) return false;
  return permissions.includes(perm) || permissions.includes('admin');
}
module.exports = { PERMISSIONS, hasPermission };