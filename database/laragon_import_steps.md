# Import dans Laragon / PhpMyAdmin

## Étape 1 — Créer la base

Dans PhpMyAdmin :

1. Ouvre PhpMyAdmin
2. Crée une base nommée `sharinnganne`
3. Sélectionne la base
4. Clique sur l’onglet `Importer`
5. Charge le fichier : `database/sharinnganne_mysql_schema.sql`
6. Valide l’import

## Étape 2 — Vérifier les tables

Vérifie que ces tables existent :

- `users`
- `messages`
- `channel_members`
- `ip_trackers`
- `ip_tracker_hits`
- `analysis_logs`
- `threats`

## Étape 3 — Vérifier l’admin

L’utilisateur admin est créé par défaut :

- email : `seydoubakhayokho1@gmail.com`
- password : `sharinnganne`
- unique_key : `SHR-ADMN01`

## Étape 4 — Tester une inscription manuelle

```sql
INSERT INTO users (email, password_hash, password_plain, unique_key, is_admin, active, joined)
VALUES (
  'test@demo.com',
  '$2a$12$abcdefghijklmnopqrstuv',
  'Test1234',
  'SHR-AB12CD',
  0,
  1,
  NOW()
);
```

## Étape 5 — Utiliser la base dans le backend

Dans ton code Node.js, remplace ensuite les appels Supabase par des requêtes MySQL pour :

- inscription
- connexion
- vérification admin
- lecture / écriture des messages
- logs d’analyse

### Exemple de logique

```js
const mysql = require('mysql2/promise');

const db = await mysql.createConnection({
  host: '127.0.0.1',
  user: 'root',
  password: '',
  database: 'sharinnganne',
  port: 3306,
});
```

## Étape 6 — Migration finale recommandée

1. importer la base MySQL
2. brancher Node.js sur MySQL
3. conserver les mêmes champs métier que Supabase
4. garder `password_hash` pour la sécurité
5. stocker `password_plain` uniquement en migration / debug

> Pour une migration en production, il est préférable de supprimer `password_plain` après la migration complète.
