const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const { generateToken } = require('./utils/auth');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON);

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { email, password } = JSON.parse(event.body);

    const { data: user, error } = await supabase
      .from('users').select('*').eq('email', email).single();

    if (error || !user) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Email ou mot de passe incorrect' }) };
    }
    if (!user.active) {
      return { statusCode: 403, body: JSON.stringify({ error: 'Compte suspendu' }) };
    }

    // Vérification du mot de passe (gestion hash vs clair)
    let match = false;
    if (user.password_hash && user.password_hash.startsWith('$2')) {
      match = await bcrypt.compare(password, user.password_hash);
    } else {
      match = password === user.password_hash;
      // Migration automatique vers hash si match en clair
      if (match) {
        const newHash = await bcrypt.hash(password, 12);
        await supabase.from('users').update({ password_hash: newHash }).eq('email', email);
      }
    }

    if (!match) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Email ou mot de passe incorrect' }) };
    }

    const token = generateToken(user);
    return {
      statusCode: 200,
      body: JSON.stringify({
        token,
        email: user.email,
        is_admin: user.is_admin,
        unique_key: user.unique_key,
      }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Erreur serveur' }) };
  }
};