const { createClient } = require('@supabase/supabase-js');
const { checkAdmin } = require('./utils/auth');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON = process.env.SUPABASE_ANON;

if (!SUPABASE_URL || !SUPABASE_ANON) {
  throw new Error("Les variables d'environnement Supabase sont manquantes.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON);

exports.handler = async (event, context) => {
  try {
    // Vérification de l'administrateur

    const { data: users, error } = await supabase
      .from('users')
      .select('id,email,is_admin,unique_key,joined,active')
      .order('joined');

    if (error) throw error;

    return {
      statusCode: 200,
      body: JSON.stringify({ total: users.length, users }),
    };
  } catch (err) {
    console.error('[Netlify Function Error]:', err);
    return {
      statusCode: err.statusCode || 500,
      body: JSON.stringify({ error: err.message || 'Erreur serveur' }),
    };
  }
};