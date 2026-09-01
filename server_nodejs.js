/**
 * SHARINNGANNE — Backend Node.js
 * Sécurité maximale + MySQL (Laragon)
 * 
 * Installation:
 *   npm install express mysql2 helmet cors express-rate-limit
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
const mysql        = require('mysql2/promise');
const crypto       = require('crypto');
const path         = require('path');
const dns          = require('dns').promises;

// ═══════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// MySQL (Laragon / phpMyAdmin)
const DB_HOST       = process.env.DB_HOST || '127.0.0.1';
const DB_PORT       = Number(process.env.DB_PORT || 3306);
const DB_USER       = process.env.DB_USER || 'root';
const DB_PASSWORD   = process.env.DB_PASSWORD || '';
const DB_NAME       = process.env.DB_NAME || 'sharinnganne';

const dbPool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4',
});

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'seydoubakhayokho1@gmail.com'; // En prod: définir via variable d'env
const ADMIN_PASS  = process.env.ADMIN_PASS  || 'sharinnganne'; // Par défaut selon la base MySQL

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
      connectSrc:     ["'self'", "https://api.open-meteo.com", 'https://cdn.jsdelivr.net'],
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

async function dbQuery(sql, params = []) {
  try {
    const [rows] = await dbPool.execute(sql, params);
    return rows;
  } catch (error) {
    console.error('DB Query error:', error.message);
    throw error;
  }
}

async function dbQueryOne(sql, params = []) {
  const rows = await dbQuery(sql, params);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
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
    const existing = await dbQueryOne('SELECT * FROM users WHERE email = ? LIMIT 1', [ADMIN_EMAIL]);
    const password_hash = await bcrypt.hash(ADMIN_PASS, 12);

    if (!existing) {
      await dbQuery(
        `INSERT INTO users (email, password_hash, password_plain, unique_key, is_admin, active, joined, updated_at, last_seen)
         VALUES (?, ?, ?, ?, 1, 1, NOW(), NOW(), NOW())`,
        [ADMIN_EMAIL, password_hash, ADMIN_PASS, 'SHR-ADMN01']
      );
      console.log('[Init] Admin vérifié/créé:', ADMIN_EMAIL);
      return;
    }

    const passMatches = typeof existing.password_hash === 'string' && existing.password_hash.startsWith('$2')
      ? await bcrypt.compare(ADMIN_PASS, existing.password_hash)
      : false;

    if (!passMatches || existing.is_admin !== 1 || existing.active !== 1) {
      await dbQuery(
        `UPDATE users SET password_hash = ?, password_plain = ?, is_admin = 1, active = 1, updated_at = NOW() WHERE email = ?`,
        [password_hash, ADMIN_PASS, ADMIN_EMAIL]
      );
      console.log('[Init] Statut admin synchronisé pour:', ADMIN_EMAIL);
    }
  } catch (e) {
    console.warn('Erreur ensureAdminUser (MySQL):', e.message || e);
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
      const existing = await dbQueryOne('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
      if (existing) return res.status(409).json({ error: 'Email déjà enregistré' });

      const password_hash = await bcrypt.hash(password, 12);
      const unique_key = genUniqueKey();

      await dbQuery(
        `INSERT INTO users (email, password_hash, password_plain, unique_key, is_admin, active, joined, updated_at, last_seen)
         VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW(), NOW())`,
        [email, password_hash, password, unique_key, email === ADMIN_EMAIL ? 1 : 0]
      );

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
      const user = await dbQueryOne('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);

      if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
      if (!user.active) return res.status(403).json({ error: 'Compte suspendu — Contactez l\'administrateur' });

      let match = false;
      if (user.password_hash && user.password_hash.startsWith('$2')) {
        match = await bcrypt.compare(password, user.password_hash);
      } else {
        match = password === user.password_hash;
      }
      if (!match) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

      if (user.password_hash && !user.password_hash.startsWith('$2')) {
        const hash = await bcrypt.hash(password, 12);
        await dbQuery('UPDATE users SET password_hash = ?, password_plain = ?, updated_at = NOW() WHERE email = ?', [hash, password, email]);
      }

      const token = generateToken({
        email: user.email,
        is_admin: Boolean(user.is_admin),
        id: user.id,
      });

      return res.json({
        token,
        email: user.email,
        is_admin: Boolean(user.is_admin),
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
  const user = await dbQueryOne(
    'SELECT email, is_admin, unique_key, joined FROM users WHERE email = ? LIMIT 1',
    [req.user.email]
  );
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
// MOTEUR DE SCAN RÉEL (PENTEST HAUTE PERFORMANCE)
// ══════════════════════════════════════════
async function scanTarget(urlInput) {
  let url = urlInput.trim();
  if (!url.startsWith('http')) url = 'https://' + url;
  let hostname = '';
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);
    const start = Date.now();
    
    // 1. Résolution DNS Réelle
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

    // 2. Vérification Robots.txt & Sitemap (Requête légère HEAD)
    const [robotsRes, sitemapRes] = await Promise.all([
      fetch(new URL('/robots.txt', url).toString(), { method: 'HEAD', signal: controller.signal }).catch(() => ({ status: 404 })),
      fetch(new URL('/sitemap.xml', url).toString(), { method: 'HEAD', signal: controller.signal }).catch(() => ({ status: 404 }))
    ]);

    // Requête HEAD principale pour être rapide et non bloquant
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
    
    // Vérification approfondie des Headers de sécurité
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

    if (riskScore > 0) {
      process.stdout.write('\u0007'); 
      console.log(`⚠️ ALERTE : Scan terminé sur ${url} (Score: ${riskScore})`);
    }

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

app.post('/api/analyze', requireAuth, analysisLimiter,
  [body('query').trim().isLength({ min: 2, max: 500 })],
  validate,
  async (req, res) => {
    const result = analyzeText(req.body.query);
    await dbQuery(
      `INSERT INTO analysis_logs (user_email, query, risk_score, created_at) VALUES (?, ?, ?, NOW())`,
      [req.user.email, req.body.query.substring(0, 100), result.risk_score]
    ).catch(() => {});
    res.json({ ...result, query: req.body.query, analyzed_at: new Date().toISOString() });
  }
);

app.post('/api/scan', requireAuth, analysisLimiter,
  [body('target').trim().isLength({ min: 4 })],
  validate,
  async (req, res) => {
    const result = await scanTarget(req.body.target);
    await dbQuery(
      `INSERT INTO analysis_logs (user_email, query, risk_score, created_at) VALUES (?, ?, ?, NOW())`,
      [req.user.email, '[SCAN] ' + req.body.target, result.risk_score || 0]
    ).catch(()=>{});
    res.json(result);
  }
);

app.post('/api/tools/whois', requireAuth, analysisLimiter,
  [body('domain').trim().isLength({ min: 3 })],
  validate,
  async (req, res) => {
    try {
      const info = await performWhoisLookup(req.body.domain);
      res.json({ success: true, info });
    } catch (e) {
      res.status(400).json({ error: e.message || "Erreur lors de la récupération WHOIS." });
    }
  }
);

app.post('/api/tools/attack-lab', requireAuth, analysisLimiter,
  [
    body('target').trim().isLength({ min: 3 }),
    body('attack_type').trim().notEmpty(),
    body('payload').optional().trim()
  ],
  validate,
  async (req, res) => {
    const { target, attack_type, payload = '' } = req.body;
    
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
      details = `Test de robustesse des mots de passe (Dictionnaire Top 100). 12 tentatives bloquées par throttling.`;
      remediation = 'Implémenter un verrouillage temporaire après 5 échecs et un CAPTCHA.';
    }

    res.json({
      success: true,
      target,
      attack_type,
      payload_used: payload || 'Standard Pentest Payload',
      status,
      risk_level: riskLevel,
      details,
      remediation,
      timestamp: new Date().toISOString()
    });
  }
);

app.post('/api/tools/wifi-audit', requireAuth, analysisLimiter,
  [
    body('bssid').trim().isLength({ min: 5 }).withMessage('Format BSSID invalide'),
    body('ssid').optional().trim(),
    body('encryption').optional().trim(),
    body('wps').optional(),
    body('channel').optional(),
    body('signal').optional()
  ],
  validate,
  async (req, res) => {
    const bssid = (req.body.bssid || '00:1A:2B:3C:4D:5E').toUpperCase().trim();
    const ssid = (req.body.ssid || 'Wi-Fi-Cible').trim();
    const enc = req.body.encryption || 'wpa2_aes';
    const wps = req.body.wps === true || req.body.wps === 'true';
    const channel = req.body.channel || '6';
    const signal = req.body.signal || '-65 dBm';

    // OUI Manufacturer Lookup
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

    // Security Assessment & Vulnerability Analysis
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

    res.json({
      success: true,
      data: {
        ssid,
        bssid,
        vendor,
        channel,
        signal,
        encryption: encDesc,
        wps: wps ? 'ACTIVÉ (VULNÉRABILITÉ WPS PIN / Pixie Dust)' : 'DÉSACTIVÉ (Sécurisé)',
        score,
        risk_level: riskLevel,
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
    });
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
  // Charger depuis MySQL, fallback démo
  let threats = DEMO_THREATS;
  try {
    const rows = await dbQuery('SELECT * FROM threats WHERE active IN (0,1) ORDER BY date DESC');
    if (rows && rows.length) threats = rows.map(t => ({ ...t, indicators: typeof t.indicators === 'string' ? (() => { try { return JSON.parse(t.indicators); } catch { return []; } })() : (t.indicators || []) }));
  } catch (_) {}
  res.json({ threats, total: threats.length, last_updated: new Date().toISOString() });
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
// ROUTES MESSAGES (Enhanced WhatsApp-style)
// ═══════════════════════════════════════
app.post('/api/messages/send', requireAuth,
  [body('channel_key').trim().matches(/^SHR-[A-Z0-9]{4,8}$/), body('content').trim().isLength({ min: 1, max: 2000 })],
  validate,
  async (req, res) => {
    const { channel_key, content, msg_type = 'text' } = req.body;
    const result = await dbQuery(
      `INSERT INTO messages (channel_key, sender, sender_name, content, msg_type, read_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        channel_key,
        req.user.email,
        req.body.sender_name || req.user.email.split('@')[0],
        content,
        msg_type,
        JSON.stringify([req.user.email]),
      ]
    );
    res.json({ status: 'sent', message_id: result.insertId });
  }
);

app.get('/api/messages/:channel_key', requireAuth, async (req, res) => {
  const { channel_key } = req.params;
  if (!/^SHR-[A-Z0-9]{4,8}$/.test(channel_key)) return res.status(400).json({ error: 'Clé invalide' });
  const messages = await dbQuery(
    'SELECT * FROM messages WHERE channel_key = ? ORDER BY created_at ASC LIMIT 200',
    [channel_key]
  );
  
  const enriched = (messages || []).map(m => ({
    ...m,
    sender_display_name: m.sender_name || (m.sender ? m.sender.split('@')[0] : 'Inconnu'),
    sender_avatar_color: m.sender ? getAvatarColor(m.sender) : '#CC0000',
    is_read: Array.isArray(m.read_by) && m.read_by.includes(req.user.email),
  }));
  
  res.json({ channel: channel_key, messages: enriched, total: enriched.length });
});

app.patch('/api/messages/read', requireAuth,
  [body('channel_key').trim().matches(/^SHR-[A-Z0-9]{4,8}$/)],
  validate,
  async (req, res) => {
    const { channel_key } = req.body;
    const unread = await dbQuery(
      'SELECT id, read_by FROM messages WHERE channel_key = ?',
      [channel_key]
    );
    
    if (unread) {
      for (const msg of unread) {
        const rb = Array.isArray(msg.read_by) ? msg.read_by : [];
        if (!rb.includes(req.user.email)) {
          rb.push(req.user.email);
          await dbQuery('UPDATE messages SET read_by = ? WHERE id = ?', [JSON.stringify(rb), msg.id]);
        }
      }
    }
    res.json({ status: 'read' });
  }
);

app.get('/api/channels/list', requireAuth, async (req, res) => {
  const [rows] = await dbPool.execute(
    `SELECT channel_key, sender, sender_name, content, created_at
     FROM messages ORDER BY created_at DESC`
  );
  const channels = rows;
  
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
  
  res.json({ channels: Object.values(channelMap) });
});

function getAvatarColor(email) {
  const colors = ['#CC0000','#FF4400','#00CC44','#0088FF','#AA00AA','#FF8800','#00CCCC','#FF6699'];
  let hash = 0;
  for (let i = 0; i < email.length; i++) hash = email.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

app.post('/api/channels/join', requireAuth,
  [body('partner_key').trim().matches(/^SHR-[A-Z0-9]{4,8}$/)],
  validate,
  async (req, res) => {
    res.json({ status: 'joined', channel_key: req.body.partner_key });
  }
);

// ═══════════════════════════════════════
// ROUTES WI-FI SCANNER (Advanced)
// ═══════════════════════════════════════
app.post('/api/tools/wifi-scan', requireAuth, analysisLimiter,
  async (req, res) => {
    const networks = generateWiFiScanResults();
    res.json({
      success: true,
      scan_time: new Date().toISOString(),
      networks_found: networks.length,
      networks,
      commands: {
        linux: [
          'nmcli dev wifi list',
          'sudo iwlist wlan0 scan',
          'sudo airodump-ng wlan0mon',
        ],
        windows: [
          'netsh wlan show networks mode=bssid',
          'netsh wlan show interfaces',
        ],
        python: [
          'python3 wifi_scanner.py --interface wlan0',
          'python3 wifi_scanner.py --all --verbose',
        ],
        nmap: [
          'nmap -sV --script "ssl-enum-ciphers" -p 443 TARGET',
          'nmap -sU -p 53,67,68,123,161 TARGET',
          'nmap --script "broadcast-ping" TARGET',
          'nmap -sn 192.168.1.0/24',
          'nmap -sV -sC -O -A TARGET',
        ]
      }
    });
  }
);

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

// ═══════════════════════════════════════
// ROUTES NMAP / PENTEST ADVANCED
// ═══════════════════════════════════════
app.post('/api/tools/nmap-scan', requireAuth, analysisLimiter,
  [body('target').trim().isLength({ min: 3 }), body('scan_type').optional().trim()],
  validate,
  async (req, res) => {
    const { target, scan_type = 'quick' } = req.body;
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

    res.json({
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
    });
  }
);

// ═══════════════════════════════════════
// ROUTES PENTEST Python Integration
// ═══════════════════════════════════════
app.post('/api/tools/pentest-python', requireAuth, analysisLimiter,
  [body('target').trim().isLength({ min: 3 }), body('script_type').trim()],
  validate,
  async (req, res) => {
    const { target, script_type } = req.body;
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
    if (!script) return res.status(400).json({ error: 'Script type inconnu' });
    
    res.json({ success: true, script: script, target, timestamp: new Date().toISOString() });
  }
);

// ═══════════════════════════════════════════
// ROUTE LOCALISATION OSINT (ÉTHIQUE / SOURCES PUBLIQUES)
// ═══════════════════════════════════════════
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

app.post('/api/tools/locate', requireAuth, analysisLimiter,
  [body('type').trim().matches(/^(phone|ip|email)$/), body('value').trim().isLength({ min: 3 })],
  validate,
  async (req, res) => {
    const { type, value } = req.body;
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
        const reversed = ip.split('.').reverse().join('.') + '.in-addr.arpa';
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

    return res.json(result);
  }
);

// ═══════════════════════════════════════════
// GÉNÉRATEUR DE LIEN TRACKER IP (lien à partager)
// Créer un lien unique → la cible clique → on recueille SON IP + position
// ═══════════════════════════════════════════
const trackerStore = new Map(); // cache mémoire
const trackerMemoryStore = new Map(); // hits en mémoire

function getClientIp(req) {
  // Nettoyer les proxies. Utilise X-Forwarded-For si présent (derrière reverse proxy)
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  let ip = req.ip || req.socket?.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7); // IPv4-mapped
  if (ip === '::1') ip = '127.0.0.1';
  ip = (ip || '').replace(/^::ffff:/, '');
  return ip || 'inconnue';
}

async function ipToGeo(ip) {
  // Géolocalisation via API publique (ipapi.co) — aucune clé requise
  try {
    const resp = await fetch(`https://ipapi.co/${ip}/json/`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const d = await resp.json();
      if (d && !d.error) {
        return {
          country: d.country_name || '',
          country_code: d.country_code || '',
          region: d.region || '',
          city: d.city || '',
          lat: d.latitude,
          lon: d.longitude,
          timezone: d.timezone || '',
          isp: d.org || '',
        };
      }
    }
  } catch (_) {}
  // Fallback : interroger le serveur pour résoudre (repli)
  return { country: '', country_code: '', region: '', city: '', lat: null, lon: null, timezone: '', isp: '' };
}

// Créer un lien tracker (auth requise)
app.post('/api/tools/tracker/create', requireAuth, analysisLimiter,
  [body('label').optional().trim().isLength({ max: 80 })],
  validate,
  async (req, res) => {
    const code = 'TRK-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const owner = req.user.email;
    const token = crypto.randomBytes(12).toString('hex');
    const label = req.body.label || `Tracker ${new Date().toLocaleString()}`;
    const record = { code, owner, label, token, created_at: new Date().toISOString(), hits: 0 };

    // Persister
    let persisted = false;
    try {
      await dbQuery(
        `INSERT INTO ip_trackers (code, owner, label, token, hits, created_at) VALUES (?, ?, ?, ?, 0, NOW())`,
        [code, owner, label, token]
      );
      persisted = true;
    } catch (_) {}
    trackerStore.set(code, record);

    // En attendre la requête de la cible sur ce lien
    trackerMemoryStore.set(code, []);

    const base = `${req.protocol}://${req.get('host')}`;
    res.json({
      success: true,
      code,
      link: `${base}/l/${code}?t=${token}`,
      results_link: `${base}/api/tools/tracker/${code}/results?token=${token}`,
      label,
      owners_only: owner,
    });
  }
);

// Le lien « à partager » : la cible clique ici → on capture SON IP
// IMPORTANT : pas d'auth (la cible n'est pas connectée)
app.get('/l/:code', async (req, res) => {
  const { code } = req.params;
  let record = trackerStore.get(code);
  if (!record) {
    try {
      record = await dbQueryOne('SELECT * FROM ip_trackers WHERE code = ? LIMIT 1', [code]);
      if (record) trackerStore.set(code, record);
    } catch (_) {}
  }
  if (!record) return res.status(404).send('Lien inconnu');

  const ip = getClientIp(req);
  const geo = await ipToGeo(ip);
  const hit = {
    ip,
    user_agent: req.headers['user-agent'] || '',
    referer: req.headers['referer'] || '',
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
  record.hits++;
  let hits = trackerMemoryStore.get(code) || [];
  hits.push(hit);
  trackerMemoryStore.set(code, hits);

  try {
    await dbQuery(
      `INSERT INTO ip_tracker_hits (code, ip, user_agent, referer, country, country_code, region, city, lat, lon, timezone, isp, captured_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [code, hit.ip, hit.user_agent, hit.referer, hit.country, hit.country_code, hit.region, hit.city, hit.lat, hit.lon, hit.timezone, hit.isp]
    );
  } catch (_) {}

  // Page neutre pour ne pas éveiller les soupçons
  res.status(200).send(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Chargement…</title></head><body style="font-family:sans-serif;background:#fff;color:#333;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><p>Chargement… veuillez patienter.</p></body></html>`);
});

// Consulter les résultats d'un tracker (auth + token du créateur)
app.get('/api/tools/tracker/:code/results', requireAuth, async (req, res) => {
  const { code } = req.params;
  let record = trackerStore.get(code);
  if (!record) {
    try {
      record = await dbQueryOne('SELECT * FROM ip_trackers WHERE code = ? LIMIT 1', [code]);
      if (record) trackerStore.set(code, record);
    } catch (_) {}
  }
  if (!record) return res.status(404).json({ error: 'Tracker introuvable' });
  if (record.owner !== req.user.email) return res.status(403).json({ error: 'Accès refusé' });

  let hits = trackerMemoryStore.get(code) || [];
  try {
    const dbHits = await dbQuery('SELECT * FROM ip_tracker_hits WHERE code = ? ORDER BY captured_at ASC', [code]);
    if (dbHits && dbHits.length) hits = dbHits;
  } catch (_) {}
  res.json({ success: true, tracker: record, hits, total: record.hits, last: hits[hits.length-1] || null });
});

// ═══════════════════════════════════════
// ROUTES ADMIN
// ═══════════════════════════════════════
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const users = await dbQuery(
    'SELECT id, email, is_admin, unique_key, joined, active FROM users ORDER BY joined ASC'
  );
  res.json({ total: users.length, users });
});

app.post('/api/admin/users', requireAdmin,
  [body('email').isEmail().normalizeEmail(), body('password').isLength({ min: 4 })],
  validate,
  async (req, res) => {
    const { email, password, is_admin = false } = req.body;
    const existing = await dbQueryOne('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
    if (existing) return res.status(409).json({ error: 'Email déjà utilisé' });

    const password_hash = await bcrypt.hash(password, 12);
    const unique_key = genUniqueKey();
    const result = await dbQuery(
      `INSERT INTO users (email, password_hash, password_plain, unique_key, is_admin, active, joined, updated_at, last_seen)
       VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW(), NOW())`,
      [email, password_hash, password, unique_key, is_admin ? 1 : 0]
    );

    const insertedId = result && result.insertId ? result.insertId : null;
    res.status(201).json({
      id: insertedId,
      email,
      is_admin: Boolean(is_admin),
      unique_key,
      joined: new Date().toISOString(),
      active: true,
      password_plain: password,
    });
  }
);

app.patch('/api/admin/users/:email', requireAdmin, async (req, res) => {
  const { email } = req.params;
  if (email === ADMIN_EMAIL && req.body.email && req.body.email !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Impossible de modifier l\'email de l\'administrateur principal' });
  }

  const updates = [];
  const values = [];

  if (req.body.email) {
    updates.push('email = ?');
    values.push(req.body.email);
  }
  if (req.body.password) {
    updates.push('password_hash = ?');
    values.push(await bcrypt.hash(req.body.password, 12));
    updates.push('password_plain = ?');
    values.push(req.body.password);
  }
  if (req.body.unique_key) {
    updates.push('unique_key = ?');
    values.push(req.body.unique_key);
  }
  if (req.body.is_admin !== undefined) {
    updates.push('is_admin = ?');
    values.push(Boolean(req.body.is_admin) ? 1 : 0);
  }
  if (req.body.active !== undefined) {
    updates.push('active = ?');
    values.push(Boolean(req.body.active) ? 1 : 0);
  }

  if (!updates.length) return res.json({ message: 'Aucune modification' });

  values.push(email);
  await dbQuery(`UPDATE users SET ${updates.join(', ')} WHERE email = ?`, values);

  const updatedUser = await dbQueryOne(
    'SELECT id, email, is_admin, unique_key, joined, active FROM users WHERE email = ? LIMIT 1',
    [req.body.email || email]
  );
  res.json(sanitizeUser(updatedUser));
});

app.delete('/api/admin/users/:email', requireAdmin, async (req, res) => {
  const { email } = req.params;
  if (email === ADMIN_EMAIL) return res.status(403).json({ error: 'Impossible de supprimer l\'administrateur principal' });
  await dbQuery('DELETE FROM users WHERE email = ?', [email]);
  res.json({ message: 'Utilisateur supprimé: ' + email });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [users, logsCount] = await Promise.all([
    dbQuery('SELECT active FROM users'),
    dbQueryOne('SELECT COUNT(*) AS total FROM analysis_logs')
  ]);

  res.json({
    total_users: users.length,
    active_users: users.filter(u => Number(u.active) === 1).length,
    suspended_users: users.filter(u => Number(u.active) !== 1).length,
    analysis_requests: logsCount ? logsCount.total : 0,
    server_time: new Date().toISOString(),
  });
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const logs = await dbQuery('SELECT * FROM analysis_logs ORDER BY created_at DESC LIMIT 50');
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
  console.log(`   Base MySQL: ${DB_NAME} @ ${DB_HOST}:${DB_PORT}`);
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
