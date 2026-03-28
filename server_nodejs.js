/**
 * SHARINNGANNE — Backend Node.js
 * Sécurité maximale + Supabase
 * 
 * Installation:
 *   npm install express @supabase/supabase-js helmet cors express-rate-limit
 *               jsonwebtoken bcryptjs express-validator morgan dotenv compression
 * 
 * Lancement: node server.js
 */

require('dotenv').config();
const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const morgan       = require('morgan');
const compression  = require('compression');
const { createClient } = require('@supabase/supabase-js');
const crypto       = require('crypto');
const path         = require('path');
const dns          = require('dns').promises;

// ═══════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Supabase (utiliser les variables d'env en production)
const SUPABASE_URL  = process.env.SUPABASE_URL  || 'https://fupsykyeofaawjekzfcz.supabase.co';
const SUPABASE_ANON = process.env.SUPABASE_ANON;

if (!SUPABASE_ANON) {
  console.error('❌ ERREUR : La variable SUPABASE_ANON est manquante dans le fichier .env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'seydoubakhayokho1@gmail.com'; // En prod: définir via variable d'env
const ADMIN_PASS  = process.env.ADMIN_PASS  || 'sharinnganne'; // Par défaut selon supabase_schema

const app = express();

// ═══════════════════════════════════════
// SÉCURITÉ — HEADERS
// ═══════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],  // Leaflet + inline
      styleSrc:       ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdn.jsdelivr.net'],
      fontSrc:        ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:         ["'self'", 'data:', 'https:'],
      connectSrc:     ["'self'", SUPABASE_URL, "https://api.open-meteo.com", 'https://cdn.jsdelivr.net'],
      frameSrc:       ["'self'", 'https://www.youtube.com', 'https://www.youtube-nocookie.com'],
      objectSrc:      ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // Cache désactivé pour les pages auth
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: false,
}));

// Cacher la technologie utilisée
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  // Empêcher la mise en cache des réponses sensibles
  res.removeHeader('ETag');
  next();
});

// ═══════════════════════════════════════
// COMPRESSION & PARSING
// ═══════════════════════════════════════
app.use(compression());
app.use(express.json({ limit: '50kb' })); // Limite la taille des requêtes
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ═══════════════════════════════════════
// CORS
// ═══════════════════════════════════════
const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN || '*', // En prod: votre domaine exact
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  credentials: true,
  maxAge: 86400,
};
app.use(cors(corsOptions));

// ═══════════════════════════════════════
// RATE LIMITING — Anti-bruteforce
// ═══════════════════════════════════════

// Limite globale
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Trop de requêtes. Réessayez dans 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Limite stricte sur les routes auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // max 10 tentatives de login en 15 min
  message: { error: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.' },
  skipSuccessfulRequests: true,
});

// Limite sur l'analyse
const analysisLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 analyses par minute
  message: { error: 'Trop d\'analyses. Réessayez dans 1 minute.' },
});

app.use(globalLimiter);

// ═══════════════════════════════════════
// LOGGING (sans données sensibles)
// ═══════════════════════════════════════
morgan.token('sanitized-url', (req) => {
  // Masquer les paramètres sensibles dans les logs
  const url = req.url;
  return url.replace(/password=[^&]*/gi, 'password=***')
            .replace(/token=[^&]*/gi, 'token=***');
});
app.use(morgan(':method :sanitized-url :status :response-time ms'));

// ═══════════════════════════════════════
// MIDDLEWARE AUTH JWT
// ═══════════════════════════════════════
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session invalide ou expirée' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Accès admin requis' });
    next();
  });
}

// ═══════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════
function genUniqueKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'SHR-' + Array.from({ length: 6 }, () =>
    chars[crypto.randomInt(chars.length)]
  ).join('');
}

function generateToken(user) {
  return jwt.sign(
    { email: user.email, is_admin: user.is_admin, uid: user.id },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '24h' }
  );
}

function sanitizeUser(user) {
  // Ne jamais renvoyer le hash du mot de passe
  const { password_hash, ...safe } = user;
  return safe;
}

// ═══════════════════════════════════════
// ANTI-INJECTION — validation entrées
// ═══════════════════════════════════════
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
}

async function ensureAdminUser() {
  try {
    const { data: existing, error: selectError } = await supabase
      .from('users').select('*').eq('email', ADMIN_EMAIL).single();

    let password_hash = await bcrypt.hash(ADMIN_PASS, 12);
    if (selectError && selectError.code !== 'PGRST116') {
      console.error('Erreur vérification admin', selectError);
    }

    if (!existing) {
      // Utilisation de upsert pour éviter les erreurs de duplication sur unique_key
      const { error: upsertError } = await supabase.from('users').upsert({
          email: ADMIN_EMAIL,
          password_hash,
          unique_key: 'SHR-ADMN01',
          is_admin: true,
          active: true,
          joined: new Date().toISOString(),
      }, { onConflict: 'email' });

      if (upsertError && upsertError.code !== '23505') {
        console.error('Erreur synchronisation admin:', upsertError.message);
      } else {
        console.log('[Init] Admin vérifié/créé:', ADMIN_EMAIL);
      }
      return;
    }

    const needsUpdate = !existing.is_admin || !existing.active;
    const passLooksHashed = typeof existing.password_hash === 'string' && existing.password_hash.startsWith('$2');
    const passMatches = passLooksHashed ? await bcrypt.compare(ADMIN_PASS, existing.password_hash) : false;
    if (!passMatches) {
      const { error: updateError } = await supabase.from('users').update({
        password_hash,
        is_admin: true,
        active: true,
      }).eq('email', ADMIN_EMAIL);
      if (updateError) console.error('Erreur mise à jour mot de passe admin', updateError);
      else console.log('[Init] Mot de passe admin mis à jour.');
      return;
    }
    if (needsUpdate) {
      const { error: updateError } = await supabase.from('users').update({
        is_admin: true,
        active: true,
      }).eq('email', ADMIN_EMAIL);
      if (updateError) console.error('Erreur mise à jour statut admin', updateError);
      else console.log('[Init] Statut admin synchronisé.');
    }
  } catch (e) {
    console.error('Erreur ensureAdminUser:', e.message || e);
  }
}

// ═══════════════════════════════════════
// VEILLE — Agrégation RSS + instantané risques
// ═══════════════════════════════════════

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
      } catch (_) { /* flux indisponible */ }
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

// ═══════════════════════════════════════
// ROUTES AUTH
// ═══════════════════════════════════════

// Inscription
app.post('/api/auth/register', authLimiter,
  [
    body('email').isEmail().normalizeEmail().withMessage('Email invalide'),
    body('password').isLength({ min: 8 }).withMessage('Mot de passe trop court (min. 8)'),
    body('accept_terms').equals('true').withMessage('Vous devez accepter les conditions'),
  ],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    try {
      // Vérifier si email existe déjà
      const { data: existing } = await supabase
        .from('users').select('id').eq('email', email).single();
      if (existing) return res.status(409).json({ error: 'Email déjà enregistré' });

      const password_hash = await bcrypt.hash(password, 12);
      const unique_key = genUniqueKey();

      const { data: user, error } = await supabase.from('users').insert({
        email,
        password_hash,
        unique_key,
        is_admin: email === ADMIN_EMAIL,
        active: true,
        joined: new Date().toISOString(),
      }).select().single();

      if (error) throw error;
      return res.status(201).json({
        message: 'Compte créé avec succès',
        unique_key,
        email,
      });
    } catch (e) {
      console.error('Register error:', e.message);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Connexion
app.post('/api/auth/login', authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    try {
      const { data: user, error } = await supabase
        .from('users').select('*').eq('email', email).single();

      if (error || !user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
      if (!user.active) return res.status(403).json({ error: 'Compte suspendu — Contactez l\'administrateur' });

      let match = false;
      if (user.password_hash && user.password_hash.startsWith('$2')) {
        match = await bcrypt.compare(password, user.password_hash);
      } else {
        match = password === user.password_hash;
      }
      if (!match) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

      // Si le mot de passe était stocké en clair, on le hashe automatiquement
      if (user.password_hash && !user.password_hash.startsWith('$2')) {
        await supabase.from('users').update({ password_hash: await bcrypt.hash(password, 12) }).eq('email', email);
      }

      const token = generateToken(user);
      return res.json({
        token,
        email: user.email,
        is_admin: user.is_admin,
        unique_key: user.unique_key,
        message: 'Connexion réussie',
      });
    } catch (e) {
      console.error('Login error:', e.message);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Profil
app.get('/api/auth/me', requireAuth, async (req, res) => {
  const { data: user } = await supabase
    .from('users').select('email,is_admin,unique_key,joined').eq('email', req.user.email).single();
  res.json(user || {});
});

// ═══════════════════════════════════════
// ROUTES ANALYSE
// ═══════════════════════════════════════
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

// ══════════════════════════════════════════
// MOTEUR DE SCAN RÉEL (PENTEST)
// ══════════════════════════════════════════
async function scanTarget(urlInput) {
  let url = urlInput.trim();
  if (!url.startsWith('http')) url = 'https://' + url;
  let hostname = '';
  
  try {
    // Timeout de 8 secondes pour le scan
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    const start = Date.now();
    
    // 1. Résolution DNS Réelle
    let ip = 'Masqué/CDN';
    try {
      hostname = new URL(url).hostname;
      const ips = await dns.resolve4(hostname).catch(() => []);
      if(ips.length > 0) ip = ips[0];
    } catch(e) {}

    // 2. Vérification Robots.txt (Passive)
    const robotsRes = await fetch(new URL('/robots.txt', url).toString(), { method: 'HEAD', signal: controller.signal }).catch(() => ({ status: 404 }));

    // Requête HEAD pour être léger et rapide
    const res = await fetch(url, { method: 'HEAD', signal: controller.signal }).catch(e => ({ error: e.message }));
    clearTimeout(timeoutId);

    if (res.error) return { error: "Cible inaccessible ou délai dépassé." };

    const headers = res.headers;
    const vulns = [];
    
    // Vérification des Headers de sécurité
    const hsts = headers.get('strict-transport-security');
    const csp = headers.get('content-security-policy');
    const xfo = headers.get('x-frame-options');
    const xct = headers.get('x-content-type-options');
    const server = headers.get('server');
    const powered = headers.get('x-powered-by');

    if(!hsts && url.startsWith('https')) vulns.push({type:'HSTS Manquant', sev:'MOYEN', desc:'Vulnérabilité aux attaques MITM (Downgrade).', fix:'Activer Strict-Transport-Security.'});
    if(!csp) vulns.push({type:'CSP Manquant', sev:'ÉLEVÉ', desc:'Protection XSS et Injection de données absente.', fix:'Définir une Content-Security-Policy stricte.'});
    if(!xfo) vulns.push({type:'Anti-Clickjacking', sev:'FAIBLE', desc:'Le site peut être intégré dans une iframe malveillante.', fix:'Ajouter X-Frame-Options: DENY.'});
    if(!xct) vulns.push({type:'MIME Sniffing', sev:'FAIBLE', desc:'Interprétation incorrecte des types de fichiers.', fix:'Ajouter X-Content-Type-Options: nosniff.'});
    if(server || powered) vulns.push({type:'Divulgation Info', sev:'INFO', desc:`Serveur expose sa version: ${server || powered}`, fix:'Masquer les en-têtes Server/X-Powered-By.'});

    let riskScore = 0;
    vulns.forEach(v => riskScore += (v.sev==='ÉLEVÉ'?30:v.sev==='MOYEN'?15:5));
    riskScore = Math.min(riskScore, 100);

    // Émettre un bip sonore dans la console du serveur si une vulnérabilité est trouvée
    if (riskScore > 0) {
      process.stdout.write('\u0007'); 
      console.log(`⚠️ ALERTE : Vulnérabilité détectée sur ${url} (Score: ${riskScore})`);
    }

    return {
      success: true,
      target: url,
      status: res.status,
      latency: Date.now() - start,
      risk_score: riskScore,
      vulns: vulns,
      real_ip: ip,
      robots_txt: robotsRes.status === 200 ? 'Trouvé (200)' : 'Non trouvé (' + robotsRes.status + ')',
      play_alert: riskScore > 0
    };
  } catch (e) {
    return { error: "Erreur moteur scan: " + e.message };
  }
}

app.post('/api/analyze', requireAuth, analysisLimiter,
  [body('query').trim().isLength({ min: 2, max: 500 })],
  validate,
  async (req, res) => {
    const result = analyzeText(req.body.query);
    // Log dans Supabase
    await supabase.from('analysis_logs').insert({
      user_email: req.user.email,
      query: req.body.query.substring(0, 100),
      risk_score: result.risk_score,
      created_at: new Date().toISOString(),
    }).catch(() => {}); // Silencieux si table inexistante
    res.json({ ...result, query: req.body.query, analyzed_at: new Date().toISOString() });
  }
);

app.post('/api/scan', requireAuth, analysisLimiter,
  [body('target').trim().isLength({ min: 4 })],
  validate,
  async (req, res) => {
    const result = await scanTarget(req.body.target);
    await supabase.from('analysis_logs').insert({
      user_email: req.user.email,
      query: '[SCAN] ' + req.body.target,
      risk_score: result.risk_score || 0,
      created_at: new Date().toISOString(),
    }).catch(()=>{});
    res.json(result);
  }
);

app.post('/api/tools/whois', requireAuth, analysisLimiter,
  [body('domain').trim().isLength({ min: 3 })],
  validate,
  async (req, res) => {
    const { domain } = req.body;
    try {
      // Extraction propre du nom de domaine
      const hostname = domain.replace(/^(?:https?:\/\/)?(?:www\.)?/i, '').split('/')[0];
      
      // Requête vers le service de redirection RDAP standard
      const response = await fetch(`https://rdap.org/domain/${hostname}`);
      
      if (!response.ok) {
        return res.status(404).json({ error: "Domaine introuvable ou extension non supportée." });
      }
      
      const data = await response.json();
      
      // Simplification des données pour l'affichage
      const simpleInfo = {
        handle: data.handle,
        events: data.events || [], // Dates (création, expiration)
        status: data.status || [],
        entities: (data.entities || []).map(e => ({ role: e.roles, name: (e.vcardArray && e.vcardArray[1]) ? e.vcardArray[1].find(x => x[0] === 'fn')?.[3] : 'N/A' }))
      };

      res.json({ success: true, info: simpleInfo });
    } catch (e) {
      res.status(500).json({ error: "Erreur lors de la récupération Whois." });
    }
  }
);

app.post('/api/tools/detect-tech', requireAuth, analysisLimiter,
  [body('url').trim().isLength({ min: 4 })],
  validate,
  async (req, res) => {
    let url = req.body.url.trim();
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

      // 1. ANALYSE HEADERS & COOKIES
      const server = headers.get('server'); const powered = headers.get('x-powered-by'); const cookies = headers.get('set-cookie') || '';
      if (server) result.web_servers.push(server);
      if (powered) { if(powered.includes('PHP')) result.languages.push('PHP'); if(powered.includes('Express')) { result.languages.push('Node.js'); result.frameworks.push('Express'); } if(powered.includes('ASP.NET')) result.languages.push('ASP.NET'); }
      if (cookies.includes('PHPSESSID')) result.languages.push('PHP');
      if (cookies.includes('JSESSIONID')) result.languages.push('Java');
      if (cookies.includes('csrftoken') && !result.languages.includes('Python')) result.languages.push('Python (Django?)');
      if (cookies.includes('laravel_session')) { result.languages.push('PHP'); result.frameworks.push('Laravel'); }

      // 2. ANALYSE HTML (SIGNATURES)
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

      Object.keys(result).forEach(k => result[k] = [...new Set(result[k])]); // Dédoublonnage
      if (result.languages.length === 0) result.languages.push('Non identifié (HTML/JS statique ?)');

      res.json({ success: true, data: result });
    } catch (e) { res.status(500).json({ error: "Échec analyse: " + e.message }); }
  }
);

app.post('/api/search/google', requireAuth,
  [body('query').trim().notEmpty()],
  validate,
  async (req, res) => {
    const q = req.body.query;
    const analysis = analyzeText(q);
    res.json({
      query: q,
      google_url: `https://www.google.com/search?q=${encodeURIComponent(q)}&hl=fr&safe=active`,
      pre_analysis: { risk_score: analysis.risk_score, risk_level: analysis.risk_level, safe_to_search: analysis.risk_score < 60, warning: analysis.recommendations[0] },
    });
  }
);

app.get('/api/threats/darkweb', requireAuth, async (req, res) => {
  // En prod: charger depuis Supabase table 'threats'
  res.json({ threats: DEMO_THREATS, total: DEMO_THREATS.length, last_updated: new Date().toISOString() });
});

app.get('/api/veille/intelligence', requireAuth, async (req, res) => {
  try {
    const items = await aggregateVeilleFeeds();
    const blob = items.map((i) => i.title).join(' ');
    const risks = computeRiskSnapshot(blob);
    res.json({
      items,
      risks,
      updated_at: new Date().toISOString(),
      source: items.length ? 'rss' : 'empty',
    });
  } catch (e) {
    console.error('Veille intelligence:', e.message || e);
    res.status(500).json({ error: 'Veille temporairement indisponible' });
  }
});

// ═══════════════════════════════════════
// ROUTES MESSAGES
// ═══════════════════════════════════════
app.post('/api/messages/send', requireAuth,
  [body('channel_key').trim().matches(/^SHR-[A-Z0-9]{4,8}$/), body('content').trim().isLength({ min: 1, max: 2000 })],
  validate,
  async (req, res) => {
    const { channel_key, content, msg_type = 'text' } = req.body;
    const { data, error } = await supabase.from('messages').insert({
      channel_key,
      sender: req.user.email,
      content,
      msg_type,
      created_at: new Date().toISOString(),
    }).select().single();
    if (error) return res.status(500).json({ error: 'Erreur envoi message' });
    res.json({ status: 'sent', message_id: data.id });
  }
);

app.get('/api/messages/:channel_key', requireAuth, async (req, res) => {
  const { channel_key } = req.params;
  if (!/^SHR-[A-Z0-9]{4,8}$/.test(channel_key)) return res.status(400).json({ error: 'Clé invalide' });
  const { data: messages } = await supabase.from('messages')
    .select('*').eq('channel_key', channel_key)
    .order('created_at', { ascending: true }).limit(100);
  res.json({ channel: channel_key, messages: messages || [], total: (messages || []).length });
});

app.post('/api/channels/join', requireAuth,
  [body('partner_key').trim().matches(/^SHR-[A-Z0-9]{4,8}$/)],
  validate,
  async (req, res) => {
    res.json({ status: 'joined', channel_key: req.body.partner_key });
  }
);

// ═══════════════════════════════════════
// ROUTES ADMIN
// ═══════════════════════════════════════
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users').select('id,email,is_admin,unique_key,joined,active').order('joined');
  if (error) return res.status(500).json({ error: 'Erreur base de données' });
  res.json({ total: users.length, users });
});

app.post('/api/admin/users', requireAdmin,
  [body('email').isEmail().normalizeEmail(), body('password').isLength({ min: 4 })],
  validate,
  async (req, res) => {
    const { email, password, is_admin = false } = req.body;
    const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
    if (existing) return res.status(409).json({ error: 'Email déjà utilisé' });
    const password_hash = await bcrypt.hash(password, 12);
    const unique_key = genUniqueKey();
    const { data: user, error } = await supabase.from('users').insert({
      email, password_hash, unique_key,
      is_admin: Boolean(is_admin),
      active: true, joined: new Date().toISOString(),
    }).select('id,email,is_admin,unique_key,joined,active').single();
    if (error) return res.status(500).json({ error: 'Erreur création' });
    // Inclure le mot de passe en clair pour l'admin (unique moment)
    res.status(201).json({ ...user, password_plain: password });
  }
);

app.patch('/api/admin/users/:email', requireAdmin, async (req, res) => {
  const { email } = req.params;
  if (email === ADMIN_EMAIL && req.body.email && req.body.email !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Impossible de modifier l\'email de l\'administrateur principal' });
  }
  const updates = {};
  if (req.body.email)     updates.email      = req.body.email;
  if (req.body.password)  updates.password_hash = await bcrypt.hash(req.body.password, 12);
  if (req.body.unique_key) updates.unique_key = req.body.unique_key;
  if (req.body.is_admin !== undefined) updates.is_admin = Boolean(req.body.is_admin);
  if (req.body.active   !== undefined) updates.active   = Boolean(req.body.active);
  const { data, error } = await supabase.from('users').update(updates).eq('email', email).select().single();
  if (error) return res.status(500).json({ error: 'Erreur mise à jour' });
  res.json(sanitizeUser(data));
});

app.delete('/api/admin/users/:email', requireAdmin, async (req, res) => {
  const { email } = req.params;
  if (email === ADMIN_EMAIL) return res.status(403).json({ error: 'Impossible de supprimer l\'administrateur principal' });
  const { error } = await supabase.from('users').delete().eq('email', email);
  if (error) return res.status(500).json({ error: 'Erreur suppression' });
  res.json({ message: 'Utilisateur supprimé: ' + email });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [usersRes, logsRes] = await Promise.all([
    supabase.from('users').select('active'),
    supabase.from('analysis_logs').select('id', { count: 'exact', head: true }),
  ]);
  const users = usersRes.data || [];
  res.json({
    total_users: users.length,
    active_users: users.filter(u => u.active).length,
    suspended_users: users.filter(u => !u.active).length,
    analysis_requests: logsRes.count || 0,
    server_time: new Date().toISOString(),
  });
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const { data: logs } = await supabase.from('analysis_logs')
    .select('*').order('created_at', { ascending: false }).limit(50);
  res.json({ logs: logs || [], total: (logs || []).length });
});

// ═══════════════════════════════════════
// HEALTHCHECK
// ═══════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'operational', service: 'SHARINNGANNE', version: '3.0.0' });
});

// ═══════════════════════════════════════
// SERVIR LE FRONTEND (fichier statique)
// ═══════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false, // Désactiver les ETags pour la sécurité
  lastModified: false,
}));
app.use('/assettes', express.static(path.join(__dirname, 'assettes')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════
// GESTION ERREURS
// ═══════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Erreur interne' });
});

// ═══════════════════════════════════════
// DÉMARRAGE
// ═══════════════════════════════════════
app.listen(PORT, async () => {
  await ensureAdminUser();
  console.log(`\n🔴 SHARINNGANNE API — Port ${PORT}`);
  console.log(`   Supabase: ${SUPABASE_URL.slice(0,40)}...`);
  console.log(`   Admin: ${ADMIN_EMAIL} (mot de passe: ${ADMIN_PASS})\n`);
});

// ═══════════════════════════════════════
// DONNÉES DEMO THREATS
// ═══════════════════════════════════════
const DEMO_THREATS = [
  {id:'DW-2026-001',category:'Data Breach',title:'Fuite massive — Opérateurs téléphoniques Afrique de l\'Ouest',description:'~2.1M entrées détectées sur un forum darknet.',severity:4,date:'2026-03-10',region:'Afrique de l\'Ouest',indicators:['telecom','mobile','senegal','wave'],recommendation:'Changez vos mots de passe. Activez la 2FA.'},
  {id:'DW-2026-002',category:'Phishing Kit',title:'Kit Phishing — Imitation Wave / Orange Money',description:'Kit ciblant le mobile money via Telegram.',severity:4,date:'2026-03-08',region:'Sénégal / Mali',indicators:['wave','orange money'],recommendation:'Ne saisissez jamais votre PIN sur un lien SMS.'},
  {id:'DW-2026-003',category:'Ransomware',title:'LockBit 3.0 — Cible PME',description:'Campagne via emails de facturation frauduleux.',severity:3,date:'2026-03-12',region:'France / Europe',indicators:['lockbit','ransomware'],recommendation:'Sauvegardez vos données régulièrement.'},
  {id:'DW-2026-006',category:'Zero-Day',title:'Exploit 0-day — Chrome < 124',description:'Exécution de code à distance.',severity:4,date:'2026-03-13',region:'Global',indicators:['chrome','exploit','zero-day'],recommendation:'Mettez à jour Chrome immédiatement.'},
];

module.exports = app;
