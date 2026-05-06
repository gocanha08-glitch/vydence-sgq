
-- Execute este SQL no Neon para atualizar permissões dos grupos existentes:
UPDATE roles SET permissions = '["dashboard","users","usuarios.gerenciar","usuarios.importar","grupos.ver","grupos.gerenciar","auditoria.ver","config.criticidades","config.matriz","config.perguntas","config.prazos","sa.avaliacao_inicial","sa.criar","sa.ver_todas","sa.aprovacao_plano","sa.concluir","sa.cancelar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar","sa.excluir","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar"]'::jsonb
WHERE name = 'Administradores';

UPDATE roles SET permissions = '["dashboard","users","auditoria.ver","config.criticidades","config.matriz","config.perguntas","config.prazos","sa.avaliacao_inicial","sa.criar","sa.ver_todas","sa.aprovacao_plano","sa.concluir","sa.cancelar","sa.abrir","sa.analisar","sa.aprovar","sa.fechar","ro.abrir","ro.analisar","ro.aprovar","ro.fechar","nc.abrir","nc.analisar","nc.aprovar","nc.fechar","riacp.abrir","riacp.analisar","riacp.aprovar","riacp.fechar"]'::jsonb
WHERE name = 'SGQ';
