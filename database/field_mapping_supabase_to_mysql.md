# Correspondance Supabase -> MySQL / Laragon

## 1) Table `users`

| Supabase | MySQL | Type | Notes |
|---|---|---|---|
| `id` | `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | identifiant interne |
| `email` | `email` | `VARCHAR(255)` | unique |
| `password_hash` | `password_hash` | `VARCHAR(255)` | hash bcrypt |
| `password_plain` | `password_plain` | `VARCHAR(255)` | optionnel, pour migration |
| `unique_key` | `unique_key` | `VARCHAR(100)` | ex: `SHR-ADMN01` |
| `is_admin` | `is_admin` | `TINYINT(1)` | 0/1 |
| `active` | `active` | `TINYINT(1)` | 0/1 |
| `joined` | `joined` | `DATETIME` | date d'inscription |
| `updated_at` | `updated_at` | `DATETIME` | dernière mise à jour |
| `display_name` | `display_name` | `VARCHAR(150)` | nom public |
| `avatar_url` | `avatar_url` | `VARCHAR(500)` | photo profil |
| `online_status` | `online_status` | `TINYINT(1)` | statut connecté |
| `last_seen` | `last_seen` | `DATETIME` | dernière activité |

### Exemple d'inscription

```sql
INSERT INTO users (
  email,
  password_hash,
  password_plain,
  unique_key,
  is_admin,
  active,
  joined
) VALUES (
  'hello@exemple.com',
  '$2a$12$abcdefghijklmnopqrstu',
  'secret123',
  'SHR-8K9Q12',
  0,
  1,
  NOW()
);
```

## 2) Table `analysis_logs`

| Supabase | MySQL | Type | Notes |
|---|---|---|---|
| `id` | `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | |
| `user_email` | `user_email` | `VARCHAR(255)` | email de l'utilisateur |
| `query` | `query` | `LONGTEXT` | requête analysée |
| `risk_score` | `risk_score` | `INT` | score de risque |
| `created_at` | `created_at` | `DATETIME` | |

## 3) Table `messages`

| Supabase | MySQL | Type | Notes |
|---|---|---|---|
| `id` | `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | |
| `channel_key` | `channel_key` | `VARCHAR(100)` | canal de discussion |
| `sender` | `sender` | `VARCHAR(255)` | expéditeur |
| `sender_name` | `sender_name` | `VARCHAR(255)` | nom affiché |
| `content` | `content` | `LONGTEXT` | contenu du message |
| `msg_type` | `msg_type` | `VARCHAR(50)` | text / file / image |
| `read_by` | `read_by` | `JSON` | liste des lecteurs |
| `delivered_at` | `delivered_at` | `DATETIME` | |
| `read_at` | `read_at` | `DATETIME` | |
| `created_at` | `created_at` | `DATETIME` | |

## 4) Table `channel_members`

| Supabase | MySQL | Type | Notes |
|---|---|---|---|
| `id` | `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | |
| `channel_key` | `channel_key` | `VARCHAR(100)` | canal |
| `email` | `email` | `VARCHAR(255)` | participant |
| `joined_at` | `joined_at` | `DATETIME` | |
| `last_read` | `last_read` | `DATETIME` | |

## 5) Table `threats`

| Supabase | MySQL | Type | Notes |
|---|---|---|---|
| `id` | `id` | `VARCHAR(100)` | identifiant de menace |
| `category` | `category` | `VARCHAR(100)` | catégorie |
| `title` | `title` | `VARCHAR(255)` | titre |
| `description` | `description` | `TEXT` | description |
| `severity` | `severity` | `INT` | niveau de gravité |
| `date` | `date` | `DATE` | date |
| `region` | `region` | `VARCHAR(150)` | région |
| `indicators` | `indicators` | `JSON` | indicateurs |
| `recommendation` | `recommendation` | `TEXT` | recommandation |
| `active` | `active` | `TINYINT(1)` | 0/1 |
| `created_at` | `created_at` | `DATETIME` | |

## 6) Règle de migration pour les inscriptions

Pour chaque nouvelle inscription, la logique correspond à :

```text
email -> users.email
password -> users.password_hash (hash bcrypt)
accept_terms -> validation côté serveur, pas forcément en base
unique_key -> users.unique_key
is_admin -> users.is_admin
active -> users.active
joined -> users.joined
```

### Exemple de logique backend

```js
const passwordHash = await bcrypt.hash(password, 12);
const uniqueKey = 'SHR-' + Math.random().toString(36).slice(2, 8).toUpperCase();

INSERT INTO users (email, password_hash, unique_key, is_admin, active, joined)
VALUES (?, ?, ?, 0, 1, NOW());
```

### Correspondance de validation

- Email : `email` -> `VARCHAR(255)` + unique
- Mot de passe : `password_hash` = `bcrypt(password)`
- Inscription: `active = 1`
- Admin: `is_admin = 1` uniquement si email administrateur
- Clé unique: `unique_key = 'SHR-' + 6 caractères` ou même format actuel

## 7) Recommandation

Tu peux garder ton schéma actuel Supabase et importer vers MySQL avec une migration simple, sans changer l’application en masse. Le changement viendra surtout du code de connexion et des requêtes SQL vers MySQL.
