function validatePassword(pwd, user = {}) {
  if (!pwd) return 'Senha obrigatoria';
  if (pwd.length < 8)  return 'Senha deve ter no minimo 8 caracteres';
  if (pwd.length > 20) return 'Senha deve ter no maximo 20 caracteres';
  if (!/[A-Z]/.test(pwd)) return 'Senha deve conter ao menos 1 letra maiuscula';
  if (!/[a-z]/.test(pwd)) return 'Senha deve conter ao menos 1 letra minuscula';
  if (!/[0-9]/.test(pwd))  return 'Senha deve conter ao menos 1 numero';
  if (!/[^A-Za-z0-9]/.test(pwd)) return 'Senha deve conter ao menos 1 caractere especial';
  if (/(.)(\1){4,}/.test(pwd)) return 'Senha nao pode conter caracteres repetidos em sequencia';

  const SEQUENCES = ['12345678','23456789','abcdefgh','qwertyui','87654321'];
  const pwdLower  = pwd.toLowerCase();
  for (const seq of SEQUENCES) {
    if (pwdLower.includes(seq)) return 'Senha nao pode conter sequencias previsiveis';
  }

  const BLACKLIST = ['senha123','admin123','mudar@123','Pass@1234','Abc@1234','Test@1234'];
  for (const weak of BLACKLIST) {
    if (pwdLower === weak.toLowerCase()) return 'Senha muito fraca ou comum';
  }

  if (user.name) {
    const parts = user.name.toLowerCase().split(/\s+/).filter(p => p.length >= 3);
    for (const part of parts) {
      if (pwdLower.includes(part)) return 'Senha nao pode conter seu nome';
    }
  }
  if (user.email) {
    const emailLocal = user.email.toLowerCase().split('@')[0];
    if (emailLocal.length >= 3 && pwdLower.includes(emailLocal)) {
      return 'Senha nao pode conter seu e-mail';
    }
  }
  return null;
}

module.exports = { validatePassword };
