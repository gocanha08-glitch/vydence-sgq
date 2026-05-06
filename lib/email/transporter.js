async function sendEmail({ to, subject, html }) {
  if (!process.env.RESEND_API_KEY) {
    console.warn('[mailer] RESEND_API_KEY nao configurada');
    return null;
  }
  const toFinal = process.env.DEV_EMAIL
    ? [process.env.DEV_EMAIL]
    : (Array.isArray(to) ? to : [to]);

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: 'SGQ Vydence <noreply@vydence.com>', to: toFinal, subject, html }),
  });
  const data = await res.json();
  if (!res.ok) { console.error('[mailer] Erro Resend:', data); return null; }
  return data;
}

module.exports = { sendEmail };
