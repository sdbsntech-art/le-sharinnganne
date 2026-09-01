const { createClient } = require('@supabase/supabase-js');
const { checkAdmin } = require('./utils/auth');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON);

exports.handler = async (event) => {
  try {
    const user = checkAdmin(event);

    const { data: users, error } = await supabase
      .from('users')
      .select('id, email, unique_key, is_admin, active, joined')
      .order('joined', { ascending: false });

    if (error) throw error;

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        users: users || [],
        total: (users || []).length,
      }),
    };
  } catch (e) {
    const status = e.statusCode || 500;
    return { statusCode: status, body: JSON.stringify({ error: e.message || 'Erreur admin' }) };
  }
};
