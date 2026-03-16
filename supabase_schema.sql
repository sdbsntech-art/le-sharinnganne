CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS public.users (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_plain TEXT,
  unique_key    TEXT UNIQUE,
  is_admin      BOOLEAN DEFAULT FALSE,
  active        BOOLEAN DEFAULT TRUE,
  joined        TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.messages (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  channel_key  TEXT NOT NULL,
  sender       TEXT NOT NULL,
  content      TEXT NOT NULL,
  msg_type     TEXT DEFAULT 'text',
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.analysis_logs (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_email  TEXT NOT NULL,
  query       TEXT NOT NULL,
  risk_score  INTEGER DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.threats (
  id             TEXT PRIMARY KEY,
  category       TEXT NOT NULL,
  title          TEXT NOT NULL,
  description    TEXT,
  severity       INTEGER DEFAULT 2,
  date           DATE DEFAULT CURRENT_DATE,
  region         TEXT DEFAULT 'Global',
  indicators     TEXT[],
  recommendation TEXT,
  active         BOOLEAN DEFAULT TRUE,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.users (email, password_hash, password_plain, unique_key, is_admin, active, joined)
VALUES (
  'seydoubakhayokho1@gmail.com',
  '$2a$12$bjDHTEh/1ces8njVokYdTOXzLUpnvOpyj379Mygdr.2LbvZV7Q7wC',
  'sharinnganne',
  'SHR-ADMN01',
  TRUE,
  TRUE,
  NOW()
) ON CONFLICT (email) DO NOTHING;

INSERT INTO public.threats (id, category, title, description, severity, date, region, indicators, recommendation) VALUES
('DW-2026-001', 'Data Breach', 'Fuite massive — Operateurs Afrique de l Ouest', '2.1M entrees detectees sur un forum darknet.', 4, '2026-03-10', 'Afrique de l Ouest', ARRAY['telecom','mobile','senegal','wave'], 'Changez vos mots de passe. Activez la 2FA.'),
('DW-2026-002', 'Phishing Kit', 'Kit Phishing — Wave / Orange Money', 'Kit ciblant le mobile money via Telegram.', 4, '2026-03-08', 'Senegal / Mali', ARRAY['wave','orange money','mobile money'], 'Ne saisissez jamais votre PIN sur un lien SMS.'),
('DW-2026-003', 'Ransomware', 'LockBit 3.0 — PME francaises', 'Campagne via emails de facturation frauduleux.', 3, '2026-03-12', 'France / Europe', ARRAY['lockbit','ransomware','facture'], 'Sauvegardez vos donnees regulierement.'),
('DW-2026-004', 'Credential Dump', '480k comptes Gmail/Yahoo compromis', 'Vente sur BreachForums.', 3, '2026-03-11', 'Global', ARRAY['gmail','yahoo','breach','dump'], 'Verifiez sur HaveIBeenPwned.'),
('DW-2026-005', 'Scam Crypto', 'Faux exchanges africains', '8 sites imitant Binance/Coinbase.', 3, '2026-03-09', 'Afrique', ARRAY['crypto','bitcoin','exchange','binance'], 'Utilisez uniquement les apps officielles.'),
('DW-2026-006', 'Zero-Day', 'Exploit Chrome < 124', 'Execution de code a distance.', 4, '2026-03-13', 'Global', ARRAY['chrome','exploit','zero-day'], 'Mettez a jour Chrome immediatement.'),
('DW-2026-007', 'Social Engineering', 'Escroquerie romance deepfake', 'Faux profils IA sur Facebook.', 2, '2026-03-07', 'Afrique / Diaspora', ARRAY['romance','facebook','deepfake'], 'Mefiez-vous des personnes demandant de l argent.')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analysis_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threats ENABLE ROW LEVEL SECURITY;

CREATE POLICY "allow_all_users" ON public.users FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "allow_all_messages" ON public.messages FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "allow_all_logs" ON public.analysis_logs FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "allow_all_threats" ON public.threats FOR ALL USING (true) WITH CHECK (true);