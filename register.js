const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const { genUniqueKey } = require('./utils/auth');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'seydoubakhayokho1@gmail.com';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { email, password, accept_terms } = JSON.parse(event.body);

    // Validation manuelle simple
    if (!email || !email.includes('@')) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Email invalide' }) };
    }
    if (!password || password.length < 8) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Mot de passe trop court (min. 8)' }) };
    }
    if (accept_terms !== true && accept_terms !== 'true') {
      return { statusCode: 400, body: JSON.stringify({ error: 'Vous devez accepter les conditions' }) };
    }

    // Vérifier si l'utilisateur existe
    const { data: existing } = await supabase
      .from('users').select('id').eq('email', email).single();
    
    if (existing) {
      return { statusCode: 409, body: JSON.stringify({ error: 'Email déjà enregistré' }) };
    }

    const password_hash = await bcrypt.hash(password, 12);
    const unique_key = genUniqueKey();

    const { error } = await supabase.from('users').insert({
      email,
      password_hash,
      unique_key,
      is_admin: email === ADMIN_EMAIL,
      active: true,
      joined: new Date().toISOString(),
    });

    if (error) throw error;

    return {
      statusCode: 201,
      body: JSON.stringify({
        message: 'Compte créé avec succès',
        unique_key,
        email,
      }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Erreur serveur' }) };
  }
};