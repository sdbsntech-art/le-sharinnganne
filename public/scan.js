const { createClient } = require('@supabase/supabase-js');
const { checkAuth } = require('./utils/auth');
const dns = require('dns').promises;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON = process.env.SUPABASE_ANON;
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON);

const FREE_HOSTS = [
  'herokuapp.com', 'netlify.app', 'vercel.app', 'github.io', 
  '000webhostapp.com', 'infinityfree.com', 'firebaseapp.com', 
  'pages.dev', 'gitlab.io', 'render.com', 'pythonanywhere.com'
];

function checkFreeHosting(url, headers) {
  const hostname = new URL(url).hostname.toLowerCase();
  const isFreeDomain = FREE_HOSTS.some(domain => hostname.endsWith(domain));
  
  const hasNetlify = headers.get('x-nf-request-id');
  const hasVercel = headers.get('x-vercel-id');
  const hasHeroku = headers.get('via') && headers.get('via').includes('vegur');

  if (isFreeDomain || hasNetlify || hasVercel || hasHeroku) {
    return {
      is_free: true,
      provider: isFreeDomain ? hostname.split('.').slice(-2).join('.') : (hasNetlify ? 'Netlify' : hasVercel ? 'Vercel' : 'Heroku'),
      note: "Hébergeur gratuit détecté."
    };
  }
  return { is_free: false, provider: headers.get('server') || 'Hébergeur Privé', note: "Hébergement professionnel." };
}

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    // 1. Vérification de l'authentification
    const user = checkAuth(event);
    const { target } = JSON.parse(event.body);
    
    if (!target) throw new Error("Cible manquante");

    let url = target.trim();
    if (!url.startsWith('http')) url = 'https://' + url;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    const start = Date.now();

    // 2. Résolution DNS
    let ip = 'Masqué/CDN';
    try {
      const hostname = new URL(url).hostname;
      const ips = await dns.resolve4(hostname).catch(() => []);
      if(ips.length > 0) ip = ips[0];
    } catch(e) {}

    // 3. Scan HTTP
    const scanHeaders = { 'User-Agent': 'Mozilla/5.0 SharinngannePentest/3.0' };
    const res = await fetch(url, { method: 'GET', headers: scanHeaders, signal: controller.signal });
    clearTimeout(timeoutId);

    const headers = res.headers;
    const hostingInfo = checkFreeHosting(url, headers);
    const vulns = [];

    // Analyse des en-têtes
    if(!headers.get('strict-transport-security') && url.startsWith('https')) 
      vulns.push({type:'HSTS Manquant', sev:'MOYEN', desc:'Vulnérabilité aux attaques MITM.', fix:'Activer HSTS.'});
    if(!headers.get('content-security-policy')) 
      vulns.push({type:'CSP Manquant', sev:'ÉLEVÉ', desc:'Protection XSS absente.', fix:'Définir une CSP.'});
    if(!headers.get('x-frame-options')) 
      vulns.push({type:'Clickjacking', sev:'FAIBLE', desc:'Intégration iframe possible.', fix:'Ajouter X-Frame-Options.'});

    let riskScore = Math.min(vulns.reduce((acc, v) => acc + (v.sev==='ÉLEVÉ'?30:v.sev==='MOYEN'?15:5), 0), 100);

    // 4. Log dans Supabase
    await supabase.from('analysis_logs').insert({
      user_email: user.email,
      query: '[SCAN] ' + url,
      risk_score: riskScore,
      created_at: new Date().toISOString(),
    }).catch(() => {});

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        target: url,
        status: res.status,
        latency: Date.now() - start,
        risk_score: riskScore,
        vulns: vulns,
        real_ip: ip,
        play_alert: riskScore > 0,
        hosting_analysis: hostingInfo
      })
    };
  } catch (err) {
    return {
      statusCode: err.statusCode || 500,
      body: JSON.stringify({ error: err.message || 'Erreur scan' }),
    };
  }
};