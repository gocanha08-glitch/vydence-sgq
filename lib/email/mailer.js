const { sendEmail } = require('./transporter');
const APP = process.env.APP_URL || '';

const header = (title) => `
<div style="background:#1570EF;padding:20px 28px;border-radius:12px 12px 0 0">
  <span style="color:#fff;font-size:16px;font-weight:600;font-family:sans-serif">Vydence Medical — SGQ</span>
  <div style="color:#BAD6FF;font-size:12px;margin-top:2px">${title}</div>
</div>`;

const footer = () => `
<div style="background:#F8FAFC;padding:14px 28px;border-radius:0 0 12px 12px;border-top:1px solid #E4E7EC">
  <span style="color:#98A2B3;font-size:11px;font-family:sans-serif">
    Sistema de Gestão da Qualidade · <a href="${APP}" style="color:#1570EF">Acessar SGQ</a>
  </span>
</div>`;

const wrap = (content) => `
<div style="background:#F4F6FB;padding:32px;font-family:sans-serif">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08)">
    ${content}
  </div>
</div>`;

async function sendResetPassword({ to, name, resetUrl }) {
  return sendEmail({
    to,
    subject: 'SGQ — Redefinição de senha',
    html: wrap(`
      ${header('Redefinição de Senha')}
      <div style="padding:24px 28px">
        <p style="color:#101828;font-size:14px">Olá <strong>${name}</strong>,</p>
        <p style="color:#475467;font-size:14px">Recebemos uma solicitação para redefinir sua senha. Clique no botão abaixo:</p>
        <a href="${resetUrl}" style="display:inline-block;background:#1570EF;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:500;margin:12px 0">Redefinir Senha</a>
        <p style="color:#98A2B3;font-size:12px;margin-top:16px">Este link expira em 1 hora. Se não foi você, ignore este e-mail.</p>
      </div>
      ${footer()}
    `)
  });
}

async function sendNewRecord({ to, code, title, module, createdBy, recordUrl }) {
  const labels = { ro:'Registro de Ocorrência', nc:'Não Conformidade', riacp:'RIACP', sa:'Controle de Mudanças' };
  return sendEmail({
    to,
    subject: `SGQ — Novo ${labels[module]||module}: ${code}`,
    html: wrap(`
      ${header(`Novo Registro — ${labels[module]||module}`)}
      <div style="padding:24px 28px">
        <p style="color:#101828;font-size:14px">Um novo registro foi aberto no SGQ:</p>
        <div style="background:#EFF4FF;border:1px solid #B2CCFF;border-radius:8px;padding:14px 16px;margin:14px 0">
          <div style="color:#1849A9;font-size:13px;font-weight:600">${code}</div>
          <div style="color:#1849A9;font-size:14px;margin-top:4px">${title}</div>
        </div>
        <p style="color:#475467;font-size:13px">Aberto por: <strong>${createdBy}</strong></p>
        <a href="${recordUrl}" style="display:inline-block;background:#1570EF;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:500;margin-top:12px">Ver Registro</a>
      </div>
      ${footer()}
    `)
  });
}

async function sendStatusChange({ to, code, title, module, newStatus, changedBy, recordUrl }) {
  return sendEmail({
    to,
    subject: `SGQ — ${code} atualizado: ${newStatus}`,
    html: wrap(`
      ${header('Atualização de Status')}
      <div style="padding:24px 28px">
        <p style="color:#101828;font-size:14px">O registro <strong>${code}</strong> foi atualizado:</p>
        <div style="background:#ECFDF3;border:1px solid #ABEFC6;border-radius:8px;padding:14px 16px;margin:14px 0">
          <div style="color:#067647;font-size:13px;font-weight:600">Novo status: ${newStatus}</div>
          <div style="color:#475467;font-size:13px;margin-top:4px">${title}</div>
        </div>
        <p style="color:#475467;font-size:13px">Atualizado por: <strong>${changedBy}</strong></p>
        <a href="${recordUrl}" style="display:inline-block;background:#1570EF;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:500;margin-top:12px">Ver Registro</a>
      </div>
      ${footer()}
    `)
  });
}

module.exports = { sendResetPassword, sendNewRecord, sendStatusChange };
