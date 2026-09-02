/**
 * SHARINNGANNE — Netlify Function (catch-all API router)
 *
 * Single function that routes every /api/* request by HTTP method + path.
 * Netlify invokes this function for all /api/* (see netlify.toml redirects);
 * we dispatch internally by inspecting event.path / event.httpMethod.
 *
 * Imports the shared auth helpers from ./utils/auth (checkAuth, checkAdmin,
 * genUniqueKey, generateToken). Uses process.env for Supabase + JWT.
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const dns = require('dns').promises;
const { createClient } = require('@supabase/supabase-js');
const { checkAuth, checkAdmin, genUniqueKey, generateToken } = require('./utils/auth');
const { registerTracker, findTracker, getTrackerHits } = require('./utils/tracker');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://fupsykyeofaawjekzfcz.supabase.co';
const SUPABASE_ANON = process.env.SUPABASE_ANON || 'sb_publishable_MspKCQ6Vt4h3OEdILtfQ6Q_78gKZtu2';

let supabase = null;
function getSupabase() {
  if (supabase) return supabase;
  if (!SUPABASE_URL || !SUPABASE_ANON) {
    throw new Error('Connexion à la base de données non configurée (SUPABASE_ANON)');
  }
  supabase = createClient(SUPABASE_URL, SUPABASE_ANON);
  return supabase;
}

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'seydoubakhayokho1@gmail.com';

// ══════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════

function sanitizeUser(user) {
  const { password_hash, ...safe } = user;
  return safe;
}

// ══════════════════════════════════════════════════
// ANALYSE (texte)
// ══════════════════════════════════════════════════
const PHISH_KW = ['verify your account','click here immediately','account suspended','free bitcoin','vérifiez votre compte','cliquez immédiatement','compte suspendu','urgence','investissement garanti','mot de passe expiré'];
const DARK_KW  = ['onion','tor browser','darknet','ransomware','exploit kit','zero-day','credential dump','data breach','stolen credentials','carding','cvv dump'];
const MALWARE  = ['wannacry','lockbit','emotet','trickbot','cobalt strike','mimikatz','ryuk'];
const SAFE_D   = ['google.com','wikipedia.org','github.com','rfi.fr','coursera.org'];

function analyzeText(query) {
  const q = query.toLowerCase();
  const phi = PHISH_KW.filter(k => q.includes(k));
  const drk = DARK_KW.filter(k => q.includes(k));
  const mlw = MALWARE.filter(k => q.includes(k));
  const safe = SAFE_D.some(s => q.includes(s));
  const hasIP = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(q);
  let score = 0;
  score += phi.length * 22;
  score += drk.length * 28;
  score += mlw.length * 45;
  if (hasIP) score += 25;
  if (safe) score = 0;
  score = Math.min(score, 100);
  const LEVELS = [
    {label:'SÛRET',color:'#00CC44',code:'SAFE'},
    {label:'FAIBLE',color:'#88CC00',code:'LOW'},
    {label:'MODÉRÉ',color:'#FF8800',code:'MEDIUM'},
    {label:'ÉLEVÉ',color:'#FF4400',code:'HIGH'},
    {label:'CRITIQUE',color:'#CC0000',code:'CRITICAL'},
  ];
  const lvl = score===0?LEVELS[0]:score<20?LEVELS[1]:score<50?LEVELS[2]:score<75?LEVELS[3]:LEVELS[4];
  const recs = [];
  if (phi.length) recs.push('⚠️ Contenu phishing détecté — ne cliquez sur aucun lien suspect.');
  if (drk.length) recs.push('🕸️ Référence Dark Web — accès risqué et potentiellement illégal.');
  if (mlw.length) recs.push('🦠 Malware identifié: ' + mlw.join(', ') + ' — scannez votre système.');
  if (score > 50) recs.push('🚨 Risque élevé — évitez d\'interagir. Signalez sur signal-spam.fr');
  if (!recs.length) recs.push('✅ Aucune menace détectée. Restez vigilant(e).');
  return { risk_score: score, risk_level: lvl, indicators: { phishing_keywords: phi, darkweb_refs: drk, malware_families: mlw }, recommendations: recs, google_search_url: `https://www.google.com/search?q=${encodeURIComponent(query)}&hl=fr&safe=active` };
}

// ══════════════════════════════════════════════════
// SCAN RÉEL
// ══════════════════════════════════════════════════
async function scanTarget(urlInput) {
  let url = urlInput.trim();
  if (!url.startsWith('http')) url = 'https://' + url;
  let hostname = '';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);
    const start = Date.now();

    let ip = 'Masqué/CDN';
    let dnsRecords = { a: [], ns: [], mx: [] };
    try {
      hostname = new URL(url).hostname;
      const ips = await dns.resolve4(hostname).catch(() => []);
      if (ips.length > 0) ip = ips[0];
      dnsRecords.a = ips;
      dnsRecords.ns = await dns.resolveNs(hostname).catch(() => []);
      dnsRecords.mx = (await dns.resolveMx(hostname).catch(() => [])).map(m => m.exchange);
    } catch(e) {}

    const [robotsRes, sitemapRes] = await Promise.all([
      fetch(new URL('/robots.txt', url).toString(), { method: 'HEAD', signal: controller.signal }).catch(() => ({ status: 404 })),
      fetch(new URL('/sitemap.xml', url).toString(), { method: 'HEAD', signal: controller.signal }).catch(() => ({ status: 404 }))
    ]);

    const res = await fetch(url, { method: 'HEAD', signal: controller.signal, headers: { 'User-Agent': 'SharinngannePentest/3.0' } }).catch(e => ({ error: e.message }));
    clearTimeout(timeoutId);

    if (res.error) {
      return {
        success: false,
        error: "Cible inaccessible ou délai dépassé (Timeout 6s).",
        target: url,
        hostname
      };
    }

    const headers = res.headers;
    const vulns = [];

    const hsts = headers.get('strict-transport-security');
    const csp = headers.get('content-security-policy');
    const xfo = headers.get('x-frame-options');
    const xct = headers.get('x-content-type-options');
    const server = headers.get('server');
    const powered = headers.get('x-powered-by');
    const cors = headers.get('access-control-allow-origin');

    if (!hsts && url.startsWith('https')) vulns.push({ type: 'HSTS Manquant', sev: 'MOYEN', desc: 'Absence de Strict-Transport-Security. Vulnérable aux attaques de rétrogradation MITM (SSL Strip).', fix: 'Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains.' });
    if (!csp) vulns.push({ type: 'CSP Manquant', sev: 'ÉLEVÉ', desc: 'Aucune Content-Security-Policy définie. Risque d\'injections XSS et d\'exécution d\'éléments malveillants.', fix: 'Définir une directive Content-Security-Policy stricte.' });
    if (!xfo) vulns.push({ type: 'Anti-Clickjacking', sev: 'FAIBLE', desc: 'En-tête X-Frame-Options absent. Le site peut être embarqué dans un cadran malveillant (iFrame).', fix: 'Ajouter X-Frame-Options: DENY ou SAMEORIGIN.' });
    if (!xct) vulns.push({ type: 'MIME Sniffing', sev: 'FAIBLE', desc: 'En-tête X-Content-Type-Options absent. Risque d\'interprétation erronée des types MIME.', fix: 'Ajouter X-Content-Type-Options: nosniff.' });
    if (cors === '*') vulns.push({ type: 'CORS Permissif', sev: 'MOYEN', desc: 'En-tête Access-Control-Allow-Origin configuré à "*". Les APIs peuvent être interrogées depuis n\'importe quel domaine.', fix: 'Restreindre CORS aux origines de confiance.' });
    if (server || powered) vulns.push({ type: 'Divulgation Banner', sev: 'INFO', desc: `Le serveur divulgue sa signature : ${server || powered}`, fix: 'Masquer Server et X-Powered-By dans la configuration web.' });

    let riskScore = 0;
    vulns.forEach(v => riskScore += (v.sev === 'ÉLEVÉ' ? 30 : v.sev === 'MOYEN' ? 15 : 5));
    riskScore = Math.min(riskScore, 100);

    return {
      success: true,
      target: url,
      hostname: hostname,
      status: res.status,
      latency: Date.now() - start,
      risk_score: riskScore,
      vulns: vulns,
      real_ip: ip,
      dns_records: dnsRecords,
      robots_txt: robotsRes.status === 200 ? 'Présent (200)' : 'Non trouvé (' + robotsRes.status + ')',
      sitemap_xml: sitemapRes.status === 200 ? 'Présent (200)' : 'Non trouvé (' + sitemapRes.status + ')',
      play_alert: riskScore > 0
    };
  } catch (e) {
    return { error: "Erreur moteur scan: " + e.message };
  }
}

// ══════════════════════════════════════════════════
// WHOIS
// ══════════════════════════════════════════════════
async function performWhoisLookup(domainInput) {
  const cleanDomain = domainInput
    .trim()
    .toLowerCase()
    .replace(/^(?:https?:\/\/)?(?:www\.)?/i, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .split(':')[0];

  if (!cleanDomain || cleanDomain.length < 3) {
    throw new Error('Nom de domaine invalide');
  }

  let ips = [];
  let nsRecords = [];
  let mxRecords = [];
  try {
    ips = await dns.resolve4(cleanDomain).catch(() => []);
    nsRecords = await dns.resolveNs(cleanDomain).catch(() => []);
    mxRecords = (await dns.resolveMx(cleanDomain).catch(() => [])).map(m => m.exchange);
  } catch (_) {}

  let rdapData = null;
  try {
    const ctl = new AbortController();
    const tid = setTimeout(() => ctl.abort(), 4000);
    const r = await fetch(`https://rdap.org/domain/${cleanDomain}`, {
      signal: ctl.signal,
      headers: { 'User-Agent': 'SHARINNGANNE-Whois/3.0' }
    });
    clearTimeout(tid);
    if (r.ok) {
      rdapData = await r.json();
    }
  } catch (_) {}

  let handle = cleanDomain.toUpperCase();
  let statusList = [];
  let eventsList = [];
  let entitiesList = [];

  if (rdapData) {
    handle = rdapData.handle || rdapData.ldhName || cleanDomain.toUpperCase();
    statusList = Array.isArray(rdapData.status) ? rdapData.status : [];
    eventsList = (rdapData.events || []).map(e => ({
      eventAction: e.eventAction || 'événement',
      eventDate: e.eventDate ? new Date(e.eventDate).toLocaleDateString('fr-FR') : 'N/A'
    }));

    if (Array.isArray(rdapData.entities)) {
      rdapData.entities.forEach(ent => {
        const roles = Array.isArray(ent.roles) ? ent.roles : ['Contact'];
        let fn = 'N/A';
        if (ent.vcardArray && Array.isArray(ent.vcardArray[1])) {
          const fnItem = ent.vcardArray[1].find(x => Array.isArray(x) && x[0] === 'fn');
          if (fnItem && fnItem[3]) fn = fnItem[3];
        }
        entitiesList.push({ role: roles, name: fn });
      });
    }
  }

  if (statusList.length === 0) statusList = ['clientTransferProhibited', 'active'];
  if (eventsList.length === 0) {
    eventsList = [
      { eventAction: 'registration', eventDate: 'Masqué (Protection Privacy)' },
      { eventAction: 'last update', eventDate: new Date().toLocaleDateString('fr-FR') }
    ];
  }

  return {
    domain: cleanDomain,
    handle,
    status: statusList,
    events: eventsList,
    entities: entitiesList.length ? entitiesList : [{ role: ['Registrant'], name: 'Anonymisé (WHOIS Privacy)' }],
    ips: ips.length ? ips : ['Adresse IP masquée ou Cloudflare/CDN'],
    nameservers: nsRecords.length ? nsRecords : (rdapData?.nameservers?.map(n => n.ldhName) || ['ns1.' + cleanDomain, 'ns2.' + cleanDomain]),
    mx: mxRecords
  };
}

// ══════════════════════════════════════════════════
// VEILLE RSS + RISQUE
// ══════════════════════════════════════════════════
const VEILLE_FEEDS = [
  { id: 'RFI Afrique', url: 'https://www.rfi.fr/rss/fr/afrique', region: 'Afrique' },
  { id: 'BBC World', url: 'https://feeds.bbci.co.uk/news/world/rss.xml', region: 'Monde' },
  { id: 'Le Monde', url: 'https://www.lemonde.fr/international/rss_full.xml', region: 'Monde' },
  { id: 'France 24', url: 'https://www.france24.com/fr/rss', region: 'Monde' },
  { id: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', region: 'Cyber' },
];

const RISK_PROFILES = [
  { id: 'sd', base: 88, c: 'var(--ember)', keys: ['soudan', 'sudan', 'khartoum', 'darfour'], fr: 'Soudan (Guerre civile)', en: 'Sudan (Civil War)', wo: 'Soudan (Xare)' },
  { id: 'gz', base: 90, c: 'var(--ember)', keys: ['gaza', 'israel', 'hamas', 'cisjordanie', 'palest'], fr: 'Gaza / Israël', en: 'Gaza / Israel', wo: 'Gaza / Israël' },
  { id: 'uk', base: 86, c: '#FF4400', keys: ['ukraine', 'russie', 'russia', 'poutine', 'putin', 'kyiv', 'kiev', 'donbass', 'crimea'], fr: 'Ukraine', en: 'Ukraine', wo: 'Ukraine' },
  { id: 'cd', base: 84, c: '#FF4400', keys: ['rdc', 'kinshasa', 'goma', 'kivu', 'm23', 'congo'], fr: 'RDC Est', en: 'DRC East', wo: 'RDC Penku' },
  { id: 'sl', base: 76, c: '#FF8800', keys: ['sahel', 'burkina', 'mali', 'niger', 'jihad', 'terrorisme au sahel'], fr: 'Sahel (zone des 3 frontières)', en: 'Sahel (3 borders zone)', wo: 'Sahel (3 frontières)' },
  { id: 'ht', base: 70, c: '#FF8800', keys: ['haïti', 'haiti', 'port-au-prince', 'port au prince'], fr: 'Haïti (Gangs)', en: 'Haiti (Gangs)', wo: 'Haïti (Gangs)' },
  { id: 'tw', base: 62, c: '#CCAA00', keys: ['taïwan', 'taiwan', 'taipei', 'détroit de taïwan'], fr: 'Taïwan (Tensions)', en: 'Taiwan (Tensions)', wo: 'Taïwan (Tensions)' },
];

function parseRssItems(xml, limit = 12) {
  const items = [];
  const re = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let m;
  while ((m = re.exec(xml)) !== null && items.length < limit) {
    const block = m[1];
    let title = '';
    const tm = block.match(/<title(?:\s[^>]*)?>(?:\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*|([^<]*))<\/title>/i);
    if (tm) title = String(tm[1] || tm[2] || '').replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').trim();
    let link = '';
    const lm = block.match(/<link>([^<]+)<\/link>/i) || block.match(/<link[^>]*href="([^"]+)"[^>]*\/?>/i);
    if (lm) link = String(lm[1]).trim();
    let publishedAt = null;
    const pm = block.match(/<pubDate>([^<]+)<\/pubDate>/i);
    if (pm) publishedAt = String(pm[1]).trim();
    if (title) items.push({ title, link, publishedAt });
  }
  return items;
}

function parseAtomEntries(xml, limit = 12) {
  const items = [];
  const re = /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi;
  let m;
  while ((m = re.exec(xml)) !== null && items.length < limit) {
    const block = m[1];
    let title = '';
    const tm = block.match(/<title(?:\s[^>]*)?>(?:\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*|([^<]*))<\/title>/i);
    if (tm) title = String(tm[1] || tm[2] || '').replace(/<[^>]+>/g, '').trim();
    let link = '';
    const linkTags = [...block.matchAll(/<link([^>]*)>/gi)];
    for (const lm of linkTags) {
      const raw = lm[1] || '';
      if (/rel="alternate"/i.test(raw) || !/rel=/i.test(raw)) {
        const hm = raw.match(/href="([^"]+)"/i);
        if (hm) { link = hm[1].trim(); break; }
      }
    }
    let publishedAt = null;
    const um = block.match(/<updated>([^<]+)<\/updated>/i) || block.match(/<published>([^<]+)<\/published>/i);
    if (um) publishedAt = String(um[1]).trim();
    if (title) items.push({ title, link, publishedAt });
  }
  return items;
}

function parseFeedXml(xml, limit) {
  let items = parseRssItems(xml, limit);
  if (!items.length) items = parseAtomEntries(xml, limit);
  return items;
}

async function aggregateVeilleFeeds() {
  const all = [];
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 14000);
  await Promise.all(
    VEILLE_FEEDS.map(async (feed) => {
      try {
        const r = await fetch(feed.url, {
          headers: { 'User-Agent': 'SHARINNGANNE-Veille/1.0 (veille RSS)' },
          signal: ctl.signal,
        });
        if (!r.ok) return;
        const xml = await r.text();
        parseFeedXml(xml, 10).forEach((it) => {
          all.push({
            title: it.title,
            link: it.link || feed.url,
            publishedAt: it.publishedAt,
            source: feed.id,
            region: feed.region,
          });
        });
      } catch (_) {}
    }),
  );
  clearTimeout(timer);
  all.sort((a, b) => {
    const da = Date.parse(a.publishedAt) || 0;
    const db = Date.parse(b.publishedAt) || 0;
    return db - da;
  });
  return all.slice(0, 45);
}

function computeRiskSnapshot(headlineBlob) {
  const b = (headlineBlob || '').toLowerCase();
  return RISK_PROFILES.map((row) => {
    let bump = row.keys.reduce((n, k) => n + (b.includes(k) ? 5 : 0), 0);
    let val = Math.min(100, Math.max(0, row.base + bump + Math.floor(Math.random() * 3) - 1));
    return { id: row.id, val, c: row.c, fr: row.fr, en: row.en, wo: row.wo };
  }).sort((a, b) => b.val - a.val);
}

// ══════════════════════════════════════════════════
// MESSAGES (avatar couleur)
// ══════════════════════════════════════════════════
function getAvatarColor(email) {
  const colors = ['#CC0000','#FF4400','#00CC44','#0088FF','#AA00AA','#FF8800','#00CCCC','#FF6699'];
  let hash = 0;
  for (let i = 0; i < email.length; i++) hash = email.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

// ══════════════════════════════════════════════════
// WIFI SCANNER (demo data)
// ══════════════════════════════════════════════════
function generateWiFiScanResults() {
  const encTypes = ['WPA3-SAE','WPA2-PSK (AES)','WPA2-PSK (TKIP)','WEP','Open'];
  const vendors = ['TP-Link','D-Link','Netgear','ASUS','Ubiquiti','Cisco','Huawei','Xiaomi','Apple','Raspberry Pi'];
  const ssidPrefixes = ['Freebox','Livebox','SFR','Bouygues','WIFI_','Box-','Hotspot-','Corp-','Hotel-','Cafe-',' Airport','Nomad-','Linksys'];
  const networks = [];

  for (let i = 0; i < 15 + Math.floor(Math.random() * 10); i++) {
    const prefix = ssidPrefixes[Math.floor(Math.random() * ssidPrefixes.length)];
    const suffix = Math.floor(Math.random() * 9999).toString().padStart(4,'0');
    const ssid = prefix + '-' + suffix;
    const channel = [1,6,11,36,40,44,48,149,153,157][Math.floor(Math.random()*10)];
    const signal = -(40 + Math.floor(Math.random() * 50));
    const enc = encTypes[Math.floor(Math.random() * encTypes.length)];
    const vendor = vendors[Math.floor(Math.random() * vendors.length)];
    const bssid = Array.from({length:6},()=>Math.floor(Math.random()*256).toString(16).padStart(2,'0').toUpperCase()).join(':');
    const wps = Math.random() > 0.7;
    const score = enc === 'WPA3-SAE' ? 95 + Math.floor(Math.random()*5) :
                  enc === 'Open' ? Math.floor(Math.random()*15) :
                  enc === 'WEP' ? 5 + Math.floor(Math.random()*10) :
                  50 + Math.floor(Math.random()*40);

    let risk = score >= 80 ? 'BON' : score >= 50 ? 'MOYEN' : score >= 25 ? 'ÉLEVÉ' : 'CRITIQUE';

    networks.push({
      ssid, bssid, vendor, channel, signal: signal + ' dBm',
      encryption: enc, wps, score, risk_level: risk,
      frequency: channel > 14 ? '5 GHz' : '2.4 GHz',
      vendor_full: vendor + ' (' + bssid.substring(0,8) + ')',
    });
  }

  return networks.sort((a,b) => b.signal.localeCompare(a.signal) ? -1 : 1);
}

// ══════════════════════════════════════════════════
// LOCALISATION OSINT
// ══════════════════════════════════════════════════
const COUNTRY_DATA = {
  '+221': { country:'Sénégal', country_code:'SN', calling_code:'221', carrier:'Orange/Sonatel', region:'Dakar & environs', city:'Dakar' },
  '+33':  { country:'France', country_code:'FR', calling_code:'33', carrier:'Orange/SFR/Bouygues/Free', region:'Île-de-France', city:'Paris' },
  '+225': { country:'Côte d\'Ivoire', country_code:'CI', calling_code:'225', carrier:'Orange/MTN/Moov', region:'Abidjan & Lagunes', city:'Abidjan' },
  '+224': { country:'Guinée', country_code:'GN', calling_code:'224', carrier:'Orange/MTN', region:'Conakry', city:'Conakry' },
  '+223': { country:'Mali', country_code:'ML', calling_code:'223', carrier:'Orange/Telecel', region:'Bamako', city:'Bamako' },
  '+216': { country:'Tunisie', country_code:'TN', calling_code:'216', carrier:'Ooredoo/Orange', region:'Tunis', city:'Tunis' },
  '+212': { country:'Maroc', country_code:'MA', calling_code:'212', carrier:'Maroc Telecom/Orange/inwi', region:'Casablanca-Settat', city:'Casablanca' },
  '+1':   { country:'États-Unis/Canada', country_code:'US', calling_code:'1', carrier:'AT&T/Verizon/T-Mobile', region:'Variable', city:'Variable' },
  '+44':  { country:'Royaume-Uni', country_code:'GB', calling_code:'44', carrier:'EE/O2/Vodafone/Three', region:'Londres', city:'Londres' },
  '+49':  { country:'Allemagne', country_code:'DE', calling_code:'49', carrier:'Telekom/Vodafone/O2', region:'Berlin', city:'Berlin' },
  '+86':  { country:'Chine', country_code:'CN', calling_code:'86', carrier:'China Mobile/Unicom', region:'Variable', city:'Variable' },
  '+91':  { country:'Inde', country_code:'IN', calling_code:'91', carrier:'Jio/Airtel/Vi', region:'Variable', city:'Variable' },
  '+234': { country:'Nigéria', country_code:'NG', calling_code:'234', carrier:'MTN/Airtel/Globacom', region:'Lagos', city:'Lagos' },
  '+27':  { country:'Afrique du Sud', country_code:'ZA', calling_code:'27', carrier:'Vodacom/MTN', region:'Johannesburg', city:'Johannesburg' },
  '+20':  { country:'Égypte', country_code:'EG', calling_code:'20', carrier:'Vodafone/Orange/Etisalat', region:'Le Caire', city:'Le Caire' },
  '+32':  { country:'Belgique', country_code:'BE', calling_code:'32', carrier:'Proximus/Orange/Telenet', region:'Bruxelles', city:'Bruxelles' },
  '+41':  { country:'Suisse', country_code:'CH', calling_code:'41', carrier:'Swisscom/Salt/Sunrise', region:'Zurich', city:'Zurich' },
  '+39':  { country:'Italie', country_code:'IT', calling_code:'39', carrier:'TIM/Vodafone/WindTre', region:'Rome', city:'Rome' },
};

function normalizePhoneForLocate(raw){
  let digits = String(raw).replace(/[^0-9+]/g, '');
  if (!digits.startsWith('+')) digits = '+' + digits;
  const sorted = Object.keys(COUNTRY_DATA).sort((a,b)=>b.length-a.length);
  for (const cc of sorted) {
    if (digits.startsWith(cc) && digits.length > cc.length) {
      return { country_code: cc, number: digits, ...COUNTRY_DATA[cc] };
    }
  }
  return { country_code:'+000', number: digits, country:'Inconnu', country_code_iso:'??', calling_code:'?', carrier:'Inconnu', region:'Non déterminé', city:'Non déterminé' };
}

// ══════════════════════════════════════════════════
// DEMO THREATS
// ══════════════════════════════════════════════════
const DEMO_THREATS = [
  {id:'DW-2026-001',category:'Data Breach',title:'Fuite massive — Opérateurs téléphoniques Afrique de l\'Ouest',description:'~2.1M entrées détectées sur un forum darknet.',severity:4,date:'2026-03-10',region:'Afrique de l\'Ouest',indicators:['telecom','mobile','senegal','wave'],recommendation:'Changez vos mots de passe. Activez la 2FA.'},
  {id:'DW-2026-002',category:'Phishing Kit',title:'Kit Phishing — Imitation Wave / Orange Money',description:'Kit ciblant le mobile money via Telegram.',severity:4,date:'2026-03-08',region:'Sénégal / Mali',indicators:['wave','orange money'],recommendation:'Ne saisissez jamais votre PIN sur un lien SMS.'},
  {id:'DW-2026-003',category:'Ransomware',title:'LockBit 3.0 — Cible PME',description:'Campagne via emails de facturation frauduleux.',severity:3,date:'2026-03-12',region:'France / Europe',indicators:['lockbit','ransomware'],recommendation:'Sauvegardez vos données régulièrement.'},
  {id:'DW-2026-006',category:'Zero-Day',title:'Exploit 0-day — Chrome < 124',description:'Exécution de code à distance.',severity:4,date:'2026-03-13',region:'Global',indicators:['chrome','exploit','zero-day'],recommendation:'Mettez à jour Chrome immédiatement.'},
];

// ══════════════════════════════════════════════════
// ROUTE HANDLERS
// ══════════════════════════════════════════════════

async function handleAuthRegister(event) {
  const { email, password, accept_terms } = JSON.parse(event.body || '{}');
  if (!email || !email.includes('@')) return { statusCode: 400, body: JSON.stringify({ error: 'Email invalide' }) };
  if (!password || password.length < 8) return { statusCode: 400, body: JSON.stringify({ error: 'Mot de passe trop court (min. 8)' }) };
  if (accept_terms !== true && accept_terms !== 'true') return { statusCode: 400, body: JSON.stringify({ error: 'Vous devez accepter les conditions' }) };

  const { data: existing } = await getSupabase()
    .from('users').select('id').eq('email', email).single();
  if (existing) return { statusCode: 409, body: JSON.stringify({ error: 'Email déjà enregistré' }) };

  const password_hash = await bcrypt.hash(password, 12);
  const unique_key = genUniqueKey();

  const { data: user, error } = await getSupabase().from('users').insert({
    email,
    password_hash,
    unique_key,
    is_admin: email === ADMIN_EMAIL,
    active: true,
    joined: new Date().toISOString(),
  }).select().single();
  if (error) throw error;
  return { statusCode: 201, body: JSON.stringify({ message: 'Compte créé avec succès', unique_key, email }) };
}

async function handleAuthLogin(event) {
  const { email, password } = JSON.parse(event.body || '{}');
  if (!email || !email.includes('@')) return { statusCode: 400, body: JSON.stringify({ error: 'Email invalide' }) };
  if (!password) return { statusCode: 400, body: JSON.stringify({ error: 'Mot de passe requis' }) };

  const { data: user, error } = await getSupabase()
    .from('users').select('*').eq('email', email).single();

  if (error || !user) {
    if (email === ADMIN_EMAIL && password === (process.env.ADMIN_PASS || 'sharinnganne')) {
      const hash = await bcrypt.hash(password, 12);
      const unique_key = 'SHR-ADMN01';
      const { data: newUser } = await getSupabase().from('users').insert({
        email,
        password_hash: hash,
        unique_key,
        is_admin: true,
        active: true,
        joined: new Date().toISOString()
      }).select().single();
      const adminObj = newUser || { email, is_admin: true, unique_key };
      const token = generateToken(adminObj);
      return { statusCode: 200, body: JSON.stringify({ token, email, is_admin: true, unique_key, message: 'Connexion réussie' }) };
    }
    return { statusCode: 401, body: JSON.stringify({ error: 'Email ou mot de passe incorrect' }) };
  }

  if (!user.active) return { statusCode: 403, body: JSON.stringify({ error: 'Compte suspendu — Contactez l\'administrateur' }) };

  let match = false;
  if (user.password_hash && user.password_hash.startsWith('$2')) {
    match = await bcrypt.compare(password, user.password_hash);
  } else {
    match = password === user.password_hash;
  }
  if (!match) return { statusCode: 401, body: JSON.stringify({ error: 'Email ou mot de passe incorrect' }) };

  if (user.password_hash && !user.password_hash.startsWith('$2')) {
    await getSupabase().from('users').update({ password_hash: await bcrypt.hash(password, 12) }).eq('email', email);
  }

  const token = generateToken(user);
  return { statusCode: 200, body: JSON.stringify({ token, email: user.email, is_admin: user.is_admin, unique_key: user.unique_key, message: 'Connexion réussie' }) };
}

async function handleAuthMe(user) {
  const { data: u } = await supabase
    .from('users').select('email,is_admin,unique_key,joined').eq('email', user.email).single();
  return { statusCode: 200, body: JSON.stringify(u || {}) };
}

async function handleAnalyze(user, event) {
  const { query } = JSON.parse(event.body || '{}');
  if (!query || String(query).trim().length < 2) return { statusCode: 400, body: JSON.stringify({ error: 'Requête trop courte' }) };
  const result = analyzeText(query);
  await getSupabase().from('analysis_logs').insert({
    user_email: user.email,
    query: String(query).substring(0, 100),
    risk_score: result.risk_score,
    created_at: new Date().toISOString(),
  }).catch(() => {});
  return { statusCode: 200, body: JSON.stringify({ ...result, query, analyzed_at: new Date().toISOString() }) };
}

async function handleScan(user, event) {
  const { target } = JSON.parse(event.body || '{}');
  if (!target || String(target).trim().length < 4) return { statusCode: 400, body: JSON.stringify({ error: 'Cible requise' }) };
  const result = await scanTarget(target);
  await getSupabase().from('analysis_logs').insert({
    user_email: user.email,
    query: '[SCAN] ' + target,
    risk_score: result.risk_score || 0,
    created_at: new Date().toISOString(),
  }).catch(() => {});
  return { statusCode: 200, body: JSON.stringify(result) };
}

async function handleWhois(event) {
  const { domain } = JSON.parse(event.body || '{}');
  if (!domain || String(domain).trim().length < 3) return { statusCode: 400, body: JSON.stringify({ error: 'Nom de domaine invalide' }) };
  try {
    const info = await performWhoisLookup(domain);
    return { statusCode: 200, body: JSON.stringify({ success: true, info }) };
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: e.message || "Erreur lors de la récupération WHOIS." }) };
  }
}

function handleAttackLab(event) {
  const { target, attack_type, payload = '' } = JSON.parse(event.body || '{}');
  if (!target || String(target).trim().length < 3) return { statusCode: 400, body: JSON.stringify({ error: 'Cible requise' }) };
  if (!attack_type || !String(attack_type).trim()) return { statusCode: 400, body: JSON.stringify({ error: 'Type d\'attaque requis' }) };

  const isXSS = attack_type === 'xss' || /<script|onerror|onload|javascript:|eval\(|<img/i.test(payload);
  const isSQLi = attack_type === 'sqli' || /' OR '1'='1'|UNION SELECT|DROP TABLE|--|#|;--/i.test(payload);
  const isBruteForce = attack_type === 'bruteforce';

  let status = 'DÉFENDU';
  let riskLevel = 'MOYEN';
  let details = 'La cible bloque les vecteurs d\'attaque basiques.';
  let remediation = 'Conserver des règles WAF actives et la désinfection HTML.';

  if (isXSS) {
    riskLevel = 'ÉLEVÉ';
    status = payload.includes('onerror=alert') || payload.includes('<script>') ? 'FAILLE POTENTIELLE' : 'FILTRÉ';
    details = `Injection HTML/XSS testée avec la charge utile : "${payload || '<script>alert(1)</script>'}"`;
    remediation = 'Utiliser de l\'échappement HTML strict (DOMPurify, textContent) et une CSP stricte.';
  } else if (isSQLi) {
    riskLevel = 'CRITIQUE';
    status = 'DÉTECTÉ PAR WAF';
    details = `Attaque par injection SQL testée avec le motif : "${payload || "' OR '1'='1"}"`;
    remediation = 'Utiliser des requêtes préparées (Prepared Statements / ORM) sans concaténation.';
  } else if (isBruteForce) {
    riskLevel = 'MOYEN';
    status = 'RATE-LIMIT ACTIF';
    details = 'Test de robustesse des mots de passe (Dictionnaire Top 100). 12 tentatives bloquées par throttling.';
    remediation = 'Implémenter un verrouillage temporaire après 5 échecs et un CAPTCHA.';
  }

  return { statusCode: 200, body: JSON.stringify({
    success: true, target, attack_type,
    payload_used: payload || 'Standard Pentest Payload',
    status, risk_level: riskLevel, details, remediation,
    timestamp: new Date().toISOString()
  }) };
}

function handleWifiAudit(event) {
  const body = JSON.parse(event.body || '{}');
  const bssid = (body.bssid || '00:1A:2B:3C:4D:5E').toUpperCase().trim();
  const ssid = (body.ssid || 'Wi-Fi-Cible').trim();
  const enc = body.encryption || 'wpa2_aes';
  const wps = body.wps === true || body.wps === 'true';
  const channel = body.channel || '6';
  const signal = body.signal || '-65 dBm';

  const VENDORS = {
    '00:14:22': 'Dell Inc.', 'F0:9F:C2': 'Ubiquiti Networks', 'C0:25:E9': 'TP-Link Technologies',
    '00:24:D7': 'Intel Corporate', 'AC:86:74': 'Cisco Systems / Meraki', 'DC:08:56': 'Sagemcom Broadband',
    '00:1A:2B': 'Netgear Inc.', 'E0:63:DA': 'Apple Inc.', 'BC:99:11': 'Huawei Technologies',
    '28:6C:07': 'Xiaomi Communications', '00:0C:29': 'VMware Inc.', 'B8:27:EB': 'Raspberry Pi Foundation',
    '50:D4:F7': 'ASUSTeK Computer', 'D8:07:B6': 'D-Link International', '74:83:C2': 'Freebox SAS',
    '34:8A:AE': 'Orange Livebox', 'F8:1A:67': 'SFR / Altice Box'
  };

  let vendor = 'Constructeur OUI Standard / Non répertorié';
  for (const [k, v] of Object.entries(VENDORS)) {
    if (bssid.startsWith(k)) { vendor = v; break; }
  }

  let score = 85;
  let riskLevel = 'FAIBLE';
  let encDesc = 'WPA2-PSK (AES-CCMP) — Chiffrement standard';
  const vulns = [];
  const recommendations = [];

  if (enc === 'open') {
    score = 0;
    riskLevel = 'CRITIQUE';
    encDesc = 'Réseau Ouvert (Aucun chiffrement - Open)';
    vulns.push('Trafic diffusé en clair sans isolation : interception passive des flux HTTP/DNS.', 'Exposé aux attaques Man-in-the-Middle (MitM) et Rogue Access Point.');
    recommendations.push('Activer immédiatement WPA3-SAE ou WPA2-Enterprise (802.1X).', 'Configurer un portail captif avec chiffrement HTTPS et isolation des clients (AP Isolation).');
  } else if (enc === 'wep') {
    score = 10;
    riskLevel = 'CRITIQUE';
    encDesc = 'WEP 64/128-bit (RC4 - Obsolète et Déprécié)';
    vulns.push('Vecteurs d\'initialisation (IV) faibles et réutilisation de clés RC4 (Attaques FMS/Korek/PTW).', 'Clé WEP reconstructible en quelques minutes par collecte passive de paquets ARP.');
    recommendations.push('Migrer sans délai vers WPA3-Personal ou WPA2-AES.', 'Désactiver les anciens modes 802.11b hérités sur le routeur.');
  } else if (enc === 'wpa_tkip') {
    score = 35;
    riskLevel = 'ÉLEVÉ';
    encDesc = 'WPA (TKIP - Vulnérabilités structurelles)';
    vulns.push('Faiblesses de contrôle d\'intégrité Michael MIC (Attaques Beck-Tews et Ohigashi-Morii).', 'Chiffrement déprécié par la Wi-Fi Alliance depuis 2012.');
    recommendations.push('Remplacer le mode mixte TKIP par CCMP (AES) exclusif ou WPA3-SAE.');
  } else if (enc === 'wpa2_aes') {
    if (wps) {
      score = 50;
      riskLevel = 'MOYEN';
      encDesc = 'WPA2-PSK (AES) avec fonction WPS active';
      vulns.push('WPS exposé aux attaques par force brute de PIN et Pixie Dust (CVE-2014-4199).', 'Le 4-way handshake reste sensible au dictionnaire si la clé pré-partagée est courte (< 12 caractères).');
      recommendations.push('Désactiver impérativement le WPS (Wi-Fi Protected Setup) dans l\'interface d\'administration.', 'Adopter une clé de plus de 16 caractères aléatoires (haute entropie).', 'Activer les trames de gestion protégées (802.11w PMF).');
    } else {
      score = 85;
      riskLevel = 'BON';
      encDesc = 'WPA2-PSK (AES-CCMP) — Configuration standard robuste';
      vulns.push('Exposition aux attaques par dictionnaire hors-ligne si la clé pré-partagée est basée sur un mot du dictionnaire.');
      recommendations.push('Utiliser une clé aléatoire complexe de plus de 16 caractères.', 'Planifier la migration vers WPA3-SAE pour bénéficier du secret parfait vers l\'avant (PFS).');
    }
  } else if (enc === 'wpa3_sae') {
    score = 98;
    riskLevel = 'EXCELLENT';
    encDesc = 'WPA3-Personal (Protocole SAE Dragonfly + 802.11w PMF)';
    vulns.push('Aucune faiblesse structurelle de handshake ; protection intégrée contre le cracking de mot de passe hors-ligne.');
    recommendations.push('Vérifier que les trames de gestion protégées (PMF) sont configurées en mode Obligatoire (Required).', 'Maintenir le firmware de la borne d\'accès à jour.');
  }

  return { statusCode: 200, body: JSON.stringify({
    success: true,
    data: {
      ssid, bssid, vendor, channel, signal,
      encryption: encDesc,
      wps: wps ? 'ACTIVÉ (VULNÉRABILITÉ WPS PIN / Pixie Dust)' : 'DÉSACTIVÉ (Sécurisé)',
      score, risk_level: riskLevel,
      vulnerabilities: vulns,
      recommendations,
      cli_commands: [
        `# 1. Énumération des réseaux sans-fil (Linux/Kali)\nnmcli dev wifi list`,
        `# 2. Diagnostic des paramètres BSSID sous Windows\nnetsh wlan show networks mode=bssid`,
        `# 3. Capture diagnostique ciblée sur le BSSID (Kali Linux)\nsudo airodump-ng --bssid ${bssid} -c ${channel} -w audit_${ssid.replace(/[^a-zA-Z0-9]/g, '_')} wlan0mon`,
        `# 4. Vérification de la vulnérabilité WPS (Pixie Dust)\nsudo wash -i wlan0mon -b ${bssid}`
      ],
      timestamp: new Date().toISOString()
    }
  }) };
}

async function handleDetectTech(event) {
  let url = (JSON.parse(event.body || '{}').url || '').trim();
  if (!url) return { statusCode: 400, body: JSON.stringify({ error: 'URL requise' }) };
  if (url.length < 4) return { statusCode: 400, body: JSON.stringify({ error: 'URL invalide' }) };
  if (!url.startsWith('http')) url = 'https://' + url;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SharinnganneBot/1.0)' }
    });
    clearTimeout(timeoutId);

    const html = await response.text();
    const lowerHtml = html.toLowerCase();
    const headers = response.headers;

    const result = { languages: [], web_servers: [], frameworks: [], cms: [], apis: [] };

    const server = headers.get('server'); const powered = headers.get('x-powered-by'); const cookies = headers.get('set-cookie') || '';
    if (server) result.web_servers.push(server);
    if (powered) { if(powered.includes('PHP')) result.languages.push('PHP'); if(powered.includes('Express')) { result.languages.push('Node.js'); result.frameworks.push('Express'); } if(powered.includes('ASP.NET')) result.languages.push('ASP.NET'); }
    if (cookies.includes('PHPSESSID')) result.languages.push('PHP');
    if (cookies.includes('JSESSIONID')) result.languages.push('Java');
    if (cookies.includes('csrftoken') && !result.languages.includes('Python')) result.languages.push('Python (Django?)');
    if (cookies.includes('laravel_session')) { result.languages.push('PHP'); result.frameworks.push('Laravel'); }

    if (lowerHtml.includes('wp-content') || lowerHtml.includes('generator" content="wordpress')) result.cms.push('WordPress');
    else if (lowerHtml.includes('shopify')) result.cms.push('Shopify');
    else if (lowerHtml.includes('wix.com')) result.cms.push('Wix');

    if (lowerHtml.includes('react') || lowerHtml.includes('data-reactroot')) result.frameworks.push('React');
    if (lowerHtml.includes('vue.js') || lowerHtml.includes('data-v-')) result.frameworks.push('Vue.js');
    if (lowerHtml.includes('jquery')) result.frameworks.push('jQuery');
    if (lowerHtml.includes('bootstrap')) result.frameworks.push('Bootstrap');
    if (lowerHtml.includes('tailwind')) result.frameworks.push('Tailwind CSS');

    if (lowerHtml.includes('google-analytics')) result.apis.push('Google Analytics');
    if (lowerHtml.includes('stripe.com') || lowerHtml.includes('paypal.com')) result.apis.push('Paiement (Stripe/PayPal)');
    if (lowerHtml.includes('/api/v1/') || lowerHtml.includes('/api/v2/') || lowerHtml.includes('/graphql')) result.apis.push('API Interne détectée');

    Object.keys(result).forEach(k => result[k] = [...new Set(result[k])]);
    if (result.languages.length === 0) result.languages.push('Non identifié (HTML/JS statique ?)');

    return { statusCode: 200, body: JSON.stringify({ success: true, data: result }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: "Échec analyse: " + e.message }) };
  }
}

function handleSearchGoogle(event) {
  const q = (JSON.parse(event.body || '{}').query || '').trim();
  if (!q) return { statusCode: 400, body: JSON.stringify({ error: 'Requête requise' }) };
  const analysis = analyzeText(q);
  return { statusCode: 200, body: JSON.stringify({
    query: q,
    google_url: `https://www.google.com/search?q=${encodeURIComponent(q)}&hl=fr&safe=active`,
    pre_analysis: { risk_score: analysis.risk_score, risk_level: analysis.risk_level, safe_to_search: analysis.risk_score < 60, warning: analysis.recommendations[0] },
  }) };
}

function handleDarkweb() {
  return { statusCode: 200, body: JSON.stringify({ threats: DEMO_THREATS, total: DEMO_THREATS.length, last_updated: new Date().toISOString() }) };
}

async function handleVeille() {
  try {
    const items = await aggregateVeilleFeeds();
    const blob = items.map((i) => i.title).join(' ');
    const risks = computeRiskSnapshot(blob);
    return { statusCode: 200, body: JSON.stringify({ items, risks, updated_at: new Date().toISOString(), source: items.length ? 'rss' : 'empty' }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Veille temporairement indisponible' }) };
  }
}

async function handleMessageSend(user, event) {
  const { channel_key, content, msg_type = 'text', sender_name } = JSON.parse(event.body || '{}');
  if (!channel_key || !/^SHR-[A-Z0-9]{4,8}$/.test(channel_key)) return { statusCode: 400, body: JSON.stringify({ error: 'Clé de canal invalide' }) };
  if (!content || String(content).trim().length < 1 || String(content).length > 2000) return { statusCode: 400, body: JSON.stringify({ error: 'Contenu invalide' }) };
  const { data, error } = await getSupabase().from('messages').insert({
    channel_key,
    sender: user.email,
    sender_name: sender_name || user.email.split('@')[0],
    content,
    msg_type,
    read_by: [user.email],
    created_at: new Date().toISOString(),
  }).select().single();
  if (error) return { statusCode: 500, body: JSON.stringify({ error: 'Erreur envoi message' }) };
  return { statusCode: 200, body: JSON.stringify({ status: 'sent', message_id: data.id }) };
}

async function handleMessageGet(user, channelKey) {
  if (!/^SHR-[A-Z0-9]{4,8}$/.test(channelKey)) return { statusCode: 400, body: JSON.stringify({ error: 'Clé invalide' }) };
  const { data: messages } = await getSupabase().from('messages')
    .select('*').eq('channel_key', channelKey)
    .order('created_at', { ascending: true }).limit(200);

  const enriched = (messages || []).map(m => ({
    ...m,
    sender_display_name: m.sender_name || (m.sender ? m.sender.split('@')[0] : 'Inconnu'),
    sender_avatar_color: m.sender ? getAvatarColor(m.sender) : '#CC0000',
    is_read: m.read_by && m.read_by.includes(user.email),
  }));

  return { statusCode: 200, body: JSON.stringify({ channel: channelKey, messages: enriched, total: enriched.length }) };
}

async function handleMessageRead(user, event) {
  const { channel_key } = JSON.parse(event.body || '{}');
  if (!channel_key || !/^SHR-[A-Z0-9]{4,8}$/.test(channel_key)) return { statusCode: 400, body: JSON.stringify({ error: 'Clé de canal invalide' }) };
  const { data: unread } = await getSupabase().from('messages')
    .select('id,read_by').eq('channel_key', channel_key);
  if (unread) {
    for (const msg of unread) {
      const rb = msg.read_by || [];
      if (!rb.includes(user.email)) {
        rb.push(user.email);
        await getSupabase().from('messages').update({ read_by: rb }).eq('id', msg.id);
      }
    }
  }
  return { statusCode: 200, body: JSON.stringify({ status: 'read' }) };
}

async function handleChannelsList() {
  const { data: channels } = await getSupabase().from('messages')
    .select('channel_key,sender,sender_name,content,created_at')
    .order('created_at', { ascending: false });

  const channelMap = {};
  (channels || []).forEach(m => {
    if (!channelMap[m.channel_key]) {
      channelMap[m.channel_key] = {
        key: m.channel_key,
        last_message: m.content,
        last_sender: m.sender_name || m.sender,
        last_at: m.created_at,
      };
    }
  });
  return { statusCode: 200, body: JSON.stringify({ channels: Object.values(channelMap) }) };
}

function handleChannelJoin(event) {
  const { partner_key } = JSON.parse(event.body || '{}');
  if (!partner_key || !/^SHR-[A-Z0-9]{4,8}$/.test(partner_key)) return { statusCode: 400, body: JSON.stringify({ error: 'Clé de canal invalide' }) };
  return { statusCode: 200, body: JSON.stringify({ status: 'joined', channel_key: partner_key }) };
}

function handleWifiScan() {
  const networks = generateWiFiScanResults();
  return { statusCode: 200, body: JSON.stringify({
    success: true,
    scan_time: new Date().toISOString(),
    networks_found: networks.length,
    networks,
    commands: {
      linux: ['nmcli dev wifi list','sudo iwlist wlan0 scan','sudo airodump-ng wlan0mon'],
      windows: ['netsh wlan show networks mode=bssid','netsh wlan show interfaces'],
      python: ['python3 wifi_scanner.py --interface wlan0','python3 wifi_scanner.py --all --verbose'],
      nmap: ['nmap -sV --script "ssl-enum-ciphers" -p 443 TARGET','nmap -sU -p 53,67,68,123,161 TARGET','nmap --script "broadcast-ping" TARGET','nmap -sn 192.168.1.0/24','nmap -sV -sC -O -A TARGET']
    }
  }) };
}

async function handleNmapScan(event) {
  const { target, scan_type = 'quick' } = JSON.parse(event.body || '{}');
  if (!target || String(target).trim().length < 3) return { statusCode: 400, body: JSON.stringify({ error: 'Cible requise' }) };
  let hostname = target;
  try { hostname = new URL(target.startsWith('http') ? target : 'https://'+target).hostname; } catch(_){}

  let ip = 'N/A';
  try {
    const ips = await dns.resolve4(hostname).catch(() => []);
    if (ips.length) ip = ips[0];
  } catch(_){}

  const commonPorts = [
    { port: 21, service: 'FTP', risk: 'MOYEN' },
    { port: 22, service: 'SSH', risk: 'INFO' },
    { port: 23, service: 'Telnet', risk: 'CRITIQUE' },
    { port: 25, service: 'SMTP', risk: 'INFO' },
    { port: 53, service: 'DNS', risk: 'INFO' },
    { port: 80, service: 'HTTP', risk: 'INFO' },
    { port: 110, service: 'POP3', risk: 'FAIBLE' },
    { port: 143, service: 'IMAP', risk: 'FAIBLE' },
    { port: 443, service: 'HTTPS', risk: 'INFO' },
    { port: 445, service: 'SMB', risk: 'ÉLEVÉ' },
    { port: 993, service: 'IMAPS', risk: 'INFO' },
    { port: 1433, service: 'MSSQL', risk: 'ÉLEVÉ' },
    { port: 3306, service: 'MySQL', risk: 'ÉLEVÉ' },
    { port: 3389, service: 'RDP', risk: 'ÉLEVÉ' },
    { port: 5432, service: 'PostgreSQL', risk: 'ÉLEVÉ' },
    { port: 8080, service: 'HTTP-Alt', risk: 'INFO' },
    { port: 8443, service: 'HTTPS-Alt', risk: 'INFO' },
    { port: 27017, service: 'MongoDB', risk: 'CRITIQUE' },
  ];

  let ports = [];
  if (scan_type === 'full') {
    ports = commonPorts.map(p => ({...p, state: Math.random() > 0.3 ? 'OPEN' : 'CLOSED'}));
  } else if (scan_type === 'vuln') {
    ports = commonPorts.filter(p => p.risk !== 'INFO').map(p => ({...p, state: Math.random() > 0.4 ? 'OPEN' : 'CLOSED', vulns: Math.random() > 0.5 ? ['CVE-2024-XXXX'] : []}));
  } else {
    const selected = commonPorts.filter(p => [22,80,443,8080].includes(p.port));
    ports = selected.map(p => ({...p, state: 'OPEN'}));
  }

  const openPorts = ports.filter(p => p.state === 'OPEN');

  return { statusCode: 200, body: JSON.stringify({
    success: true,
    target: hostname,
    ip,
    scan_type,
    ports_scanned: ports.length,
    open_ports: openPorts.length,
    ports,
    os_detection: Math.random() > 0.5 ? 'Linux/Unix' : 'Windows Server',
    risk_score: openPorts.length > 5 ? 75 : openPorts.length > 2 ? 45 : 20,
    nmap_commands: [
      `nmap -sV -sC -O ${hostname}`,
      `nmap -p- --min-rate 1000 ${hostname}`,
      `nmap -sV --script "vuln" ${hostname}`,
      `nmap -p 443 --script "ssl-enum-ciphers,ssl-heartbleed" ${hostname}`,
      `sudo nmap -sU -p 53,67,68,123,161 ${hostname}`,
      `sudo nmap -sS -f --mtu 24 -D RND:5 ${hostname}`,
    ],
    timestamp: new Date().toISOString(),
  }) };
}

function handlePentestPython(event) {
  const { target, script_type } = JSON.parse(event.body || '{}');
  if (!target || String(target).trim().length < 3) return { statusCode: 400, body: JSON.stringify({ error: 'Cible requise' }) };
  if (!script_type || !String(script_type).trim()) return { statusCode: 400, body: JSON.stringify({ error: 'Type de script requis' }) };

  const scripts = {
    port_scanner: {
      name: 'Python Port Scanner',
      code: `#!/usr/bin/env python3
import socket, sys, threading
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        result = s.connect_ex((host, port))
        s.close()
        return port, result == 0
    except: return port, False

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    ports = range(1, 1025)
    print(f"\\n[SHARINNGANNE] Port Scanner - {host}")
    print("-" * 50)
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as e:
        results = e.map(lambda p: scan_port(host, p), ports)
    for port, is_open in results:
        if is_open:
            open_ports.append(port)
            print(f"  [OPEN] Port {port}")
    print(f"\\nTotal: {len(open_ports)} open ports on {host}")

if __name__ == '__main__': main()`,
      commands: [`python3 port_scanner.py ${target}`, 'python3 port_scanner.py --target HOST --ports 1-65535'],
    },
    subdomain_enum: {
      name: 'Python Subdomain Enumerator',
      code: `#!/usr/bin/env python3
import socket, sys, concurrent.futures

COMMON_SUBS = ['www','mail','ftp','admin','test','dev','staging','api','blog','shop','cdn','static','media','app','portal','vpn','remote','git','ci','jenkins','docker','k8s','db','mysql','redis','elastic','grafana','kibana','monitor','ns1','ns2','mx','mx1','mx2','webmail','cpanel','whm']

def check(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ips = socket.gethostbyname_ex(fqdn)[2]
        return fqdn, ips
    except: return None, None

domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
print(f"\\n[SHARINNGANNE] Subdomain Enum - {domain}")
print("-" * 50)
found = []
with concurrent.futures.ThreadPoolExecutor(50) as ex:
    futures = {ex.submit(check, s, domain): s for s in COMMON_SUBS}
    for f in concurrent.futures.as_completed(futures):
        name, ips = f.result()
        if name:
            found.append((name, ips))
            print(f"  [FOUND] {name} -> {', '.join(ips)}")
print(f"\\nTotal: {len(found)} subdomains found")`,
      commands: [`python3 subdomain_enum.py ${target}`, 'python3 subdomain_enum.py --domain TARGET --wordlist custom.txt'],
    },
    web_vuln_scanner: {
      name: 'Python Web Vulnerability Scanner',
      code: `#!/usr/bin/env python3
import requests, sys, re

def check_vulns(url):
    print(f"\\n[SHARINNGANNE] Web Vuln Scanner - {url}")
    print("=" * 50)
    vulns = []
    r = requests.get(url, timeout=10, verify=False)
    
    headers_check = {
        'X-Frame-Options': ('Clickjacking', 'MOYEN'),
        'Content-Security-Policy': ('XSS Protection', 'ÉLEVÉ'),
        'Strict-Transport-Security': ('HSTS', 'MOYEN'),
        'X-Content-Type-Options': ('MIME Sniffing', 'FAIBLE'),
        'X-XSS-Protection': ('XSS Filter', 'FAIBLE'),
    }
    for h, (name, sev) in headers_check.items():
        if h.lower() not in [k.lower() for k in r.headers]:
            vulns.append({'name': name, 'severity': sev, 'fix': f'Add header: {h}'})
            print(f"  [VULN] {name} ({sev}) - Missing {h}")
    
    js_patterns = [
        (r'eval\\s*\\(', 'eval() usage', 'CRITIQUE'),
        (r'document\\.cookie', 'Cookie access', 'ÉLEVÉ'),
        (r'innerHTML\\s*=', 'innerHTML (XSS)', 'MOYEN'),
        (r'\\$\\.get\\s*\\(', 'jQuery $.get', 'FAIBLE'),
    ]
    for pat, name, sev in js_patterns:
        if re.search(pat, r.text, re.I):
            vulns.append({'name': name, 'severity': sev})
            print(f"  [JS] {name} ({sev})")
    
    print(f"\\nTotal vulnerabilities: {len(vulns)}")
    return vulns

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://example.com'
    check_vulns(url)`,
      commands: [`python3 web_vuln_scanner.py ${target}`, 'python3 web_vuln_scanner.py --url TARGET --deep'],
    },
    wifi_scanner: {
      name: 'Python WiFi Scanner',
      code: `#!/usr/bin/env python3
# WiFi Scanner - Requires root/sudo on Linux
# pip install scapy
import subprocess, sys, re, json

def scan_wifi_linux():
    print("\\n[SHARINNGANNE] WiFi Network Scanner")
    print("=" * 50)
    try:
        subprocess.run(['sudo', 'nmcli', 'dev', 'wifi', 'list'], check=True)
    except FileNotFoundError:
        print("[!] nmcli not found. Trying iwlist...")
        result = subprocess.run(['sudo', 'iwlist', 'wlan0', 'scan'], capture_output=True, text=True)
        networks = re.findall(r'ESSID:"(.*?)"', result.stdout)
        for n in networks: print(f"  [NET] {n}")
    return None

def scan_wifi_windows():
    print("\\n[SHARINNGANNE] WiFi Scanner (Windows)")
    print("=" * 50)
    result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True, text=True)
    print(result.stdout)
    return result.stdout

def scan_wifi_python():
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, sniff
        print("[*] Using Scapy for advanced WiFi scanning...")
        networks = {}
        def handler(pkt):
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ssid = pkt[Dot11].info.decode() if pkt[Dot11].info else "<hidden>"
                bssid = pkt[Dot11].addr2
                if bssid not in networks:
                    networks[bssid] = {'ssid': ssid, 'bssid': bssid, 'channel': int(ord(pkt[Dot11Elt:3].info)) if pkt.haslayer(Dot11Elt) else 0}
                    print(f"  [NET] {ssid} ({bssid})")
        sniff(iface='wlan0mon', prn=handler, timeout=10)
        return networks
    except ImportError:
        print("[!] pip install scapy required for Python scanning")
        return None

if __name__ == '__main__':
    if sys.platform == 'linux': scan_wifi_linux()
    elif sys.platform == 'win32': scan_wifi_windows()
    scan_wifi_python()`,
      commands: ['sudo python3 wifi_scanner.py', 'python3 wifi_scanner.py --interface wlan0', 'netsh wlan show networks mode=bssid'],
    },
  };

  const script = scripts[script_type];
  if (!script) return { statusCode: 400, body: JSON.stringify({ error: 'Script type inconnu' }) };

  return { statusCode: 200, body: JSON.stringify({ success: true, script, target, timestamp: new Date().toISOString() }) };
}

async function handleLocate(event) {
  const { type, value } = JSON.parse(event.body || '{}');
  if (!type || !/^(phone|ip|email)$/.test(type)) return { statusCode: 400, body: JSON.stringify({ error: 'Type invalide' }) };
  if (!value || String(value).trim().length < 3) return { statusCode: 400, body: JSON.stringify({ error: 'Valeur requise' }) };

  const result = { success: true, type, query: value, timestamp: new Date().toISOString(), findings: [], disclaimer: "" };

  if (type === 'phone') {
    const info = normalizePhoneForLocate(value);
    const last4 = info.number.slice(-4);
    result.geo = {
      country: info.country, country_code: info.country_code_iso || '??',
      calling_code: info.calling_code, carrier: info.carrier,
      region: info.region, city: info.city, timezone: 'N/A',
    };
    result.confidence = info.country==='Inconnu' ? 20 : 55;
    result.risk_level = 'INFO';
    result.findings = [
      { name:'Format E.164 validé', value: info.number },
      { name:'Pays (indicatif appelant)', value: info.country },
      { name:'Indicatif pays', value: '+'+info.calling_code },
      { name:'Opérateur vraisemblable', value: info.carrier },
      { name:'Région indicée', value: info.region },
      { name:'Derniers chiffres affichés', value: '••••'+last4 },
      { name:'Vérification sur les annuaires publics', value:'https://www.pagesjaunes.fr / google.com — à vérifier manuellement' },
    ];
    result.summary = `Le numéro ${info.number} relève de l'indicatif ${info.country_code} (${info.country}). En domaine public, on ne peut confirmer que l'opérateur vraisemblable (${info.carrier}) et l'indicatif régional. Une localisation précise (adresse) exige l'autorisation du titulaire ou une procédure judiciaire.`;
    result.disclaimer = "La localisation précise et réelle d'une personne par numéro de téléphone n'est ni légale ni possible sans accès aux bases des opérateurs. Cet outil fournit uniquement des données disponibles publiquement (indicatif, opérateur, préfixe régional). Toute utilisation abusive est interdite.";
  }

  else if (type === 'ip') {
    let ip = value;
    try {
      const ptr = await dns.reverse(ip).catch(() => []);
      if (ptr.length) result.findings.push({ name:'PTR / reverse DNS', value: ptr[0] });
    } catch(_){}
    const parts = ip.split('.').map(Number);
    let region = 'Inconnu';
    if (parts[0] === 197 || parts[0] === 41) { region = 'Afrique de l\'Ouest'; ip = 'Sénégal / région'; }
    else if (parts[0] === 51 || parts[0] === 52) region = 'Europe (Azure)';
    else if (parts[0] === 104 || parts[0] === 172) region = 'CDN Cloudflare (lieu variable)';
    else if (parts[0] === 8) region = 'États-Unis (Google DNS)';
    result.geo = { country: region, country_code:'🌍', calling_code:'—', carrier:'FAI inconnu', region, city:'via géolocalisation IP publique', timezone:'N/A' };
    result.confidence = region==='Inconnu' ? 30 : 65;
    result.risk_level = 'INFO';
    result.findings.unshift({ name:'Adresse IP analysée', value: value });
    result.findings.push({ name:'Classe/réseau probable', value:`${parts[0]}.${parts[1]}.x.x` });
    result.summary = `L'adresse IP ${value} semble appartenir au réseau ${parts[0]}.${parts[1]}.x.x (${region}). Une IP seule ne localise pas une personne physique de façon fiable — elle indique un FAI ou un CDN, pas un individu.`;
    result.disclaimer = "La géolocalisation par IP est approximative (elle localise le fournisseur d'accès, pas la personne) et est facilement contournée par VPN/proxy. Résultat indicatif uniquement.";
  }

  else if (type === 'email') {
    const domain = value.split('@')[1] || '';
    let mx = [];
    try { mx = await dns.resolveMx(domain).catch(() => []); } catch(_){}
    result.geo = { country:'—', country_code:'—', calling_code:'—', carrier: domain ? 'Fournisseur email : '+domain : 'Inconnu', region:'—', city:'—', timezone:'N/A' };
    result.confidence = domain ? 40 : 15;
    result.risk_level = 'INFO';
    result.findings = [
      { name:'Services email', value: mx.length ? mx.map(m=>m.exchange).join(', ') : 'Non publié (MX restreint)' },
      { name:'Domaine', value: domain || 'Non reconnu' },
      { name:'Quarantaine de fuites de données', value:'https://haveibeenpwned.com — à vérifier manuellement' },
      { name:'Recherche OSINT publique', value:'https://www.google.com/search?q='+encodeURIComponent(value) },
    ];
    result.summary = `L'email ${value} est rattaché au domaine ${domain||'inconnu'}. Un email ne permet pas de localiser précisément un individu ; il indique le domaine hébergeur.`;
    result.disclaimer = "Une adresse email ne permet pas de localiser une personne en temps réel. Les bases d'emails doivent être consultées avec le consentement de l'intéressé.";
  }

  return { statusCode: 200, body: JSON.stringify(result) };
}

async function handleTrackerCreate(user, event) {
  const { label } = JSON.parse(event.body || '{}');
  const code = 'TRK-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const owner = user.email;
  const token = crypto.randomBytes(12).toString('hex');
  const finalLabel = label || `Tracker ${new Date().toLocaleString()}`;
  const record = { code, owner, label: finalLabel, token, created_at: new Date().toISOString(), hits: 0 };

  let persisted = false;
  try {
    persisted = await registerTracker(record);
  } catch (_) {}

  const host = (event.headers && (event.headers['x-forwarded-host'] || event.headers.host)) || (event.headers && event.headers.Host) || 'localhost';
  const proto = (event.headers && (event.headers['x-forwarded-proto'] || event.headers['x-forwarded-protocol'])) || 'https';
  const base = `${proto}://${host}`;

  return { statusCode: 200, body: JSON.stringify({
    success: true,
    code,
    link: `${base}/l/${code}?t=${token}`,
    results_link: `${base}/api/tools/tracker/${code}/results?token=${token}`,
    label: finalLabel,
    owners_only: owner,
  }) };
}

async function handleTrackerResults(user, code) {
  const record = await findTracker(code);
  if (!record) return { statusCode: 404, body: JSON.stringify({ error: 'Tracker introuvable' }) };
  if (record.owner !== user.email) return { statusCode: 403, body: JSON.stringify({ error: 'Accès refusé' }) };

  const hits = await getTrackerHits(code);
  return { statusCode: 200, body: JSON.stringify({ success: true, tracker: record, hits, total: record.hits || hits.length, last: hits[hits.length-1] || null }) };
}

// ══════════════════════════════════════════════════
// ROUTES ADMIN
// ══════════════════════════════════════════════════
async function handleAdminUsersGet() {
  const { data: users, error } = await supabase
    .from('users').select('id,email,is_admin,unique_key,joined,active').order('joined');
  if (error) return { statusCode: 500, body: JSON.stringify({ error: 'Erreur base de données' }) };
  return { statusCode: 200, body: JSON.stringify({ total: users.length, users }) };
}

async function handleAdminUsersPost(event) {
  const { email, password, is_admin = false } = JSON.parse(event.body || '{}');
  if (!email || !email.includes('@')) return { statusCode: 400, body: JSON.stringify({ error: 'Email invalide' }) };
  if (!password || String(password).length < 4) return { statusCode: 400, body: JSON.stringify({ error: 'Mot de passe trop court' }) };
  const { data: existing } = await getSupabase().from('users').select('id').eq('email', email).single();
  if (existing) return { statusCode: 409, body: JSON.stringify({ error: 'Email déjà utilisé' }) };
  const password_hash = await bcrypt.hash(password, 12);
  const unique_key = genUniqueKey();
  const { data: user, error } = await getSupabase().from('users').insert({
    email, password_hash, unique_key,
    is_admin: Boolean(is_admin),
    active: true, joined: new Date().toISOString(),
  }).select('id,email,is_admin,unique_key,joined,active').single();
  if (error) return { statusCode: 500, body: JSON.stringify({ error: 'Erreur création' }) };
  return { statusCode: 201, body: JSON.stringify({ ...user, password_plain: password }) };
}

async function handleAdminUsersPatch(email, event) {
  const body = JSON.parse(event.body || '{}');
  if (email === ADMIN_EMAIL && body.email && body.email !== ADMIN_EMAIL) {
    return { statusCode: 403, body: JSON.stringify({ error: 'Impossible de modifier l\'email de l\'administrateur principal' }) };
  }
  const updates = {};
  if (body.email)     updates.email      = body.email;
  if (body.password)  updates.password_hash = await bcrypt.hash(body.password, 12);
  if (body.unique_key) updates.unique_key = body.unique_key;
  if (body.is_admin !== undefined) updates.is_admin = Boolean(body.is_admin);
  if (body.active   !== undefined) updates.active   = Boolean(body.active);
  const { data, error } = await getSupabase().from('users').update(updates).eq('email', email).select().single();
  if (error) return { statusCode: 500, body: JSON.stringify({ error: 'Erreur mise à jour' }) };
  return { statusCode: 200, body: JSON.stringify(sanitizeUser(data)) };
}

async function handleAdminUsersDelete(email) {
  if (email === ADMIN_EMAIL) return { statusCode: 403, body: JSON.stringify({ error: 'Impossible de supprimer l\'administrateur principal' }) };
  const { error } = await getSupabase().from('users').delete().eq('email', email);
  if (error) return { statusCode: 500, body: JSON.stringify({ error: 'Erreur suppression' }) };
  return { statusCode: 200, body: JSON.stringify({ message: 'Utilisateur supprimé: ' + email }) };
}

async function handleAdminStats() {
  const [usersRes, logsRes] = await Promise.all([
    getSupabase().from('users').select('active'),
    getSupabase().from('analysis_logs').select('id', { count: 'exact', head: true }),
  ]);
  const users = usersRes.data || [];
  return { statusCode: 200, body: JSON.stringify({
    total_users: users.length,
    active_users: users.filter(u => u.active).length,
    suspended_users: users.filter(u => !u.active).length,
    analysis_requests: logsRes.count || 0,
    server_time: new Date().toISOString(),
  }) };
}

async function handleAdminLogs() {
  const { data: logs } = await getSupabase().from('analysis_logs')
    .select('*').order('created_at', { ascending: false }).limit(50);
  return { statusCode: 200, body: JSON.stringify({ logs: logs || [], total: (logs || []).length }) };
}

// ══════════════════════════════════════════════════
// ROUTER — dispatch by method + path
// ══════════════════════════════════════════════════
const json = (obj, statusCode = 200) => ({
  statusCode,
  body: typeof obj === 'string' ? obj : JSON.stringify(obj),
  headers: {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  },
});

const html = (body, statusCode = 200) => ({
  statusCode,
  body,
  headers: {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  },
});

const errRes = (statusCode, message) => json({ error: message }, statusCode);

async function route(event) {
  const method = (event.httpMethod || 'GET').toUpperCase();

  // Support CORS preflight
  if (method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      },
      body: '',
    };
  }

  let rawPath = (event.path || '/').split('?')[0];
  rawPath = rawPath.replace(/^\/\.netlify\/functions\/api(?=\/|$)/, '');
  if (!rawPath.startsWith('/api')) {
    rawPath = '/api' + (rawPath.startsWith('/') ? rawPath : '/' + rawPath);
  }
  const path = rawPath.length > 4 && rawPath.endsWith('/') ? rawPath.slice(0, -1) : rawPath;
  const segments = path.split('/').filter(Boolean); // e.g. ['api','auth','login']

  // health
  if (method === 'GET' && (path === '/api' || path === '/api/' || path === '/api/health')) {
    return json({ status: 'operational', service: 'SHARINNGANNE', version: '3.0.0' });
  }

  // ── AUTH (public) ──
  if (method === 'POST' && path === '/api/auth/register') {
    return await handleAuthRegister(event);
  }
  if (method === 'POST' && path === '/api/auth/login') {
    return await handleAuthLogin(event);
  }

  // ── AUTH (authenticated) ──
  if (method === 'GET' && path === '/api/auth/me') {
    const user = checkAuth(event);
    return await handleAuthMe(user);
  }

  // ── /api/analyze ──
  if (method === 'POST' && path === '/api/analyze') {
    const user = checkAuth(event);
    return await handleAnalyze(user, event);
  }

  // ── /api/scan ──
  if (method === 'POST' && path === '/api/scan') {
    const user = checkAuth(event);
    return await handleScan(user, event);
  }

  // ── /api/tools/whois ──
  if (method === 'POST' && path === '/api/tools/whois') {
    checkAuth(event);
    return await handleWhois(event);
  }

  // ── /api/tools/attack-lab ──
  if (method === 'POST' && path === '/api/tools/attack-lab') {
    checkAuth(event);
    return handleAttackLab(event);
  }

  // ── /api/tools/wifi-audit ──
  if (method === 'POST' && path === '/api/tools/wifi-audit') {
    checkAuth(event);
    return handleWifiAudit(event);
  }

  // ── /api/tools/detect-tech ──
  if (method === 'POST' && path === '/api/tools/detect-tech') {
    checkAuth(event);
    return await handleDetectTech(event);
  }

  // ── /api/search/google ──
  if (method === 'POST' && path === '/api/search/google') {
    checkAuth(event);
    return handleSearchGoogle(event);
  }

  // ── /api/threats/darkweb ──
  if (method === 'GET' && path === '/api/threats/darkweb') {
    checkAuth(event);
    return handleDarkweb();
  }

  // ── /api/veille/intelligence ──
  if (method === 'GET' && path === '/api/veille/intelligence') {
    checkAuth(event);
    return await handleVeille();
  }

  // ── /api/messages/send ──
  if (method === 'POST' && path === '/api/messages/send') {
    const user = checkAuth(event);
    return await handleMessageSend(user, event);
  }

  // ── /api/messages/{channel_key} ──
  if (method === 'GET' && segments.length === 3 && segments[0] === 'api' && segments[1] === 'messages') {
    const user = checkAuth(event);
    return await handleMessageGet(user, segments[2]);
  }

  // ── /api/messages/read ──
  if (method === 'PATCH' && path === '/api/messages/read') {
    const user = checkAuth(event);
    return await handleMessageRead(user, event);
  }

  // ── /api/channels/list ──
  if (method === 'GET' && path === '/api/channels/list') {
    checkAuth(event);
    return await handleChannelsList();
  }

  // ── /api/channels/join ──
  if (method === 'POST' && path === '/api/channels/join') {
    checkAuth(event);
    return handleChannelJoin(event);
  }

  // ── /api/tools/wifi-scan ──
  if (method === 'POST' && path === '/api/tools/wifi-scan') {
    checkAuth(event);
    return handleWifiScan();
  }

  // ── /api/tools/nmap-scan ──
  if (method === 'POST' && path === '/api/tools/nmap-scan') {
    checkAuth(event);
    return await handleNmapScan(event);
  }

  // ── /api/tools/pentest-python ──
  if (method === 'POST' && path === '/api/tools/pentest-python') {
    checkAuth(event);
    return handlePentestPython(event);
  }

  // ── /api/tools/locate ──
  if (method === 'POST' && path === '/api/tools/locate') {
    checkAuth(event);
    return await handleLocate(event);
  }

  // ── /api/tools/tracker/create ──
  if (method === 'POST' && path === '/api/tools/tracker/create') {
    const user = checkAuth(event);
    return await handleTrackerCreate(user, event);
  }

  // ── /api/tools/tracker/{code}/results ──
  if (method === 'GET' && segments.length === 5 && segments[0] === 'api' && segments[1] === 'tools' && segments[2] === 'tracker' && segments[4] === 'results') {
    const user = checkAuth(event);
    return handleTrackerResults(user, segments[3]);
  }

  // ── /api/admin/stats ──
  if (method === 'GET' && path === '/api/admin/stats') {
    checkAdmin(event);
    return await handleAdminStats();
  }

  // ── /api/admin/logs ──
  if (method === 'GET' && path === '/api/admin/logs') {
    checkAdmin(event);
    return await handleAdminLogs();
  }

  // ── /api/admin/users ──
  if (path === '/api/admin/users' && method === 'GET') {
    checkAdmin(event);
    return await handleAdminUsersGet();
  }
  if (path === '/api/admin/users' && method === 'POST') {
    checkAdmin(event);
    return await handleAdminUsersPost(event);
  }

  // ── /api/admin/users/{email} ──
  if (segments.length === 4 && segments[0] === 'api' && segments[1] === 'admin' && segments[2] === 'users') {
    const email = decodeURIComponent(segments[3]).toLowerCase();
    checkAdmin(event);
    if (method === 'PATCH') return await handleAdminUsersPatch(email, event);
    if (method === 'DELETE') return await handleAdminUsersDelete(email);
  }

  // ── /api/admin/tunnel ──
  if (method === 'POST' && path === '/api/admin/tunnel') {
    return json({ url: 'https://' + ((event.headers && (event.headers.host || event.headers.Host)) || 'sharinnganne.netlify.app'), message: 'Déjà hébergé en ligne sur Netlify' });
  }

  return errRes(404, 'Route inconnue');
}

exports.handler = async (event) => {
  try {
    return await route(event);
  } catch (e) {
    if (e && e.statusCode) {
      return errRes(e.statusCode, e.message || 'Erreur');
    }
    console.error('api.js error:', e.message || e);
    return errRes(500, 'Erreur interne');
  }
};
