CREATE DATABASE IF NOT EXISTS sharinnganne CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sharinnganne;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    password_plain VARCHAR(255) NULL,
    unique_key VARCHAR(100) NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    active TINYINT(1) NOT NULL DEFAULT 1,
    joined DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    display_name VARCHAR(150) NULL,
    avatar_url VARCHAR(500) NULL,
    online_status TINYINT(1) NOT NULL DEFAULT 0,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email),
    UNIQUE KEY uq_users_unique_key (unique_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    channel_key VARCHAR(100) NOT NULL,
    sender VARCHAR(255) NOT NULL,
    sender_name VARCHAR(255) NULL,
    content LONGTEXT NOT NULL,
    msg_type VARCHAR(50) NOT NULL DEFAULT 'text',
    read_by JSON NULL DEFAULT ('[]'),
    delivered_at DATETIME NULL,
    read_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_messages_channel (channel_key),
    KEY idx_messages_sender (sender)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS channel_members (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    channel_key VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_read DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_channel_members (channel_key, email),
    KEY idx_channel_members_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip_trackers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code VARCHAR(100) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    label VARCHAR(255) NULL,
    token VARCHAR(255) NOT NULL,
    hits INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ip_trackers_code (code),
    KEY idx_ip_trackers_owner (owner)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip_tracker_hits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code VARCHAR(100) NOT NULL,
    ip VARCHAR(100) NULL,
    user_agent TEXT NULL,
    referer TEXT NULL,
    country VARCHAR(100) NULL,
    country_code VARCHAR(10) NULL,
    region VARCHAR(150) NULL,
    city VARCHAR(150) NULL,
    lat DOUBLE NULL,
    lon DOUBLE NULL,
    timezone VARCHAR(100) NULL,
    isp VARCHAR(200) NULL,
    captured_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_ip_tracker_hits_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS analysis_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_email VARCHAR(255) NOT NULL,
    query LONGTEXT NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_analysis_logs_user (user_email),
    KEY idx_analysis_logs_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS threats (
    id VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    severity INT NOT NULL DEFAULT 2,
    date DATE NULL,
    region VARCHAR(150) NOT NULL DEFAULT 'Global',
    indicators JSON NULL,
    recommendation TEXT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_threats_region (region)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO users (email, password_hash, password_plain, unique_key, is_admin, active, joined)
VALUES (
    'seydoubakhayokho1@gmail.com',
    '$2a$12$bjDHTEh/1ces8njVokYdTOXzLUpnvOpyj379Mygdr.2LbvZV7Q7wC',
    'sharinnganne',
    'SHR-ADMN01',
    1,
    1,
    NOW()
)
ON DUPLICATE KEY UPDATE
    password_hash = VALUES(password_hash),
    password_plain = VALUES(password_plain),
    unique_key = VALUES(unique_key),
    is_admin = VALUES(is_admin),
    active = VALUES(active);

INSERT INTO threats (id, category, title, description, severity, date, region, indicators, recommendation)
VALUES
    ('DW-2026-001', 'Data Breach', 'Fuite massive — Operateurs Afrique de l Ouest', '2.1M entrees detectees sur un forum darknet.', 4, '2026-03-10', 'Afrique de l Ouest', JSON_ARRAY('telecom','mobile','senegal','wave'), 'Changez vos mots de passe. Activez la 2FA.'),
    ('DW-2026-002', 'Phishing Kit', 'Kit Phishing — Wave / Orange Money', 'Kit ciblant le mobile money via Telegram.', 4, '2026-03-08', 'Senegal / Mali', JSON_ARRAY('wave','orange money','mobile money'), 'Ne saisissez jamais votre PIN sur un lien SMS.'),
    ('DW-2026-003', 'Ransomware', 'LockBit 3.0 — PME francaises', 'Campagne via emails de facturation frauduleux.', 3, '2026-03-12', 'France / Europe', JSON_ARRAY('lockbit','ransomware','facture'), 'Sauvegardez vos donnees regulierement.'),
    ('DW-2026-004', 'Credential Dump', '480k comptes Gmail/Yahoo compromis', 'Vente sur BreachForums.', 3, '2026-03-11', 'Global', JSON_ARRAY('gmail','yahoo','breach','dump'), 'Verifiez sur HaveIBeenPwned.'),
    ('DW-2026-005', 'Scam Crypto', 'Faux exchanges africains', '8 sites imitant Binance/Coinbase.', 3, '2026-03-09', 'Afrique', JSON_ARRAY('crypto','bitcoin','exchange','binance'), 'Utilisez uniquement les apps officielles.'),
    ('DW-2026-006', 'Zero-Day', 'Exploit Chrome < 124', 'Execution de code a distance.', 4, '2026-03-13', 'Global', JSON_ARRAY('chrome','exploit','zero-day'), 'Mettez a jour Chrome immediatement.'),
    ('DW-2026-007', 'Social Engineering', 'Escroquerie romance deepfake', 'Faux profils IA sur Facebook.', 2, '2026-03-07', 'Afrique / Diaspora', JSON_ARRAY('romance','facebook','deepfake'), 'Mefiez-vous des personnes demandant de l argent.')
ON DUPLICATE KEY UPDATE
    category = VALUES(category),
    title = VALUES(title),
    description = VALUES(description),
    severity = VALUES(severity),
    date = VALUES(date),
    region = VALUES(region),
    indicators = VALUES(indicators),
    recommendation = VALUES(recommendation),
    active = VALUES(active);

SELECT 'Base SHARINNGANNE prête pour Laragon / PhpMyAdmin' AS status;
