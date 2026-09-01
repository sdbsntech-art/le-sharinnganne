/**
 * SHARINNGANNE — Tracker helpers shared by api.js and l.js
 *
 * NOTE : sur Netlify, chaque fonction a sa propre mémoire. L'état du
 * tracker (création → consultation des résultats → clic public) est donc
 * partagé via Supabase (tables ip_trackers / ip_tracker_hits), avec un
 * cache mémoire local par invocation pour rester conforme au serveur.
 */

const { createClient } = require('@supabase/supabase-js');

let supabase = null;
function getSupabase() {
  if (supabase) return supabase;
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON) return null;
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON);
  return supabase;
}

function getClientIp(event) {
  const headers = event.headers || {};
  const fwd = headers['x-forwarded-for'] || headers['X-Forwarded-For'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  let ip = (event.headers && (event.headers['client-ip'] || event.headers['x-real-ip'])) || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
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
  return { country: '', country_code: '', region: '', city: '', lat: null, lon: null, timezone: '', isp: '' };
}

// Retrouve un tracker : mémoire locale d'abord, Supabase ensuite.
async function findTracker(code) {
  const localStore = globalThis.__shr_trackerStore || new Map();
  if (localStore.has(code)) return localStore.get(code);
  try {
    const sb = getSupabase();
    if (!sb) return null;
    const { data } = await sb.from('ip_trackers').select('*').eq('code', code).single();
    if (data) {
      localStore.set(code, data);
      return data;
    }
  } catch (_) {}
  return null;
}

function localStore() {
  if (!globalThis.__shr_trackerStore) globalThis.__shr_trackerStore = new Map();
  return globalThis.__shr_trackerStore;
}

function localHits() {
  if (!globalThis.__shr_trackerHits) globalThis.__shr_trackerHits = new Map();
  return globalThis.__shr_trackerHits;
}

async function registerTracker(record) {
  const store = localStore();
  store.set(record.code, record);
  localHits().set(record.code, []);
  try {
    const sb = getSupabase();
    if (!sb) return false;
    const { error } = await sb.from('ip_trackers').insert(record);
    return !error;
  } catch (_) {
    return false;
  }
}

async function recordHit(code, hit) {
  let record = await findTracker(code);
  if (!record) return null;
  if (record.hits === undefined) record.hits = 0;
  record.hits++;
  const hits = localHits().get(code) || [];
  hits.push(hit);
  localHits().set(code, hits);
  try {
    const sb = getSupabase();
    if (!sb) return;
    await sb.from('ip_tracker_hits').insert({ code, ...hit });
  } catch (_) {}
  return record;
}

async function getTrackerHits(code) {
  const hits = localHits().get(code);
  if (hits && hits.length) return hits;
  try {
    const sb = getSupabase();
    if (!sb) return [];
    const { data } = await sb.from('ip_tracker_hits').select('*').eq('code', code).order('captured_at', { ascending: true });
    return data || [];
  } catch (_) {
    return [];
  }
}

module.exports = { getClientIp, ipToGeo, findTracker, registerTracker, recordHit, getTrackerHits, localStore, localHits };