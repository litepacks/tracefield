# tracefield 🛡️

[![GitHub](https://img.shields.io/badge/github-litepacks%2Ftracefield-blue.svg)](https://github.com/litepacks/tracefield)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](#)

**`tracefield`** is an ultra-fast, zero-dependency Node.js and Edge security middleware, scanner probe detector, and honeypot deception engine. It sits at the very beginning of the HTTP request lifecycle to detect automated reconnaissance, exploit-path enumeration, and secret discovery attempts.

When suspicious scanners request sensitive paths (like `/.env`, `/.git/config`, `/.ssh/id_rsa`, or `/wp-config.php`), `tracefield` can optionally respond with **realistic, completely fake decoy configurations** (including ASCII troll face RSA keys, fake JWTs, FTP configs, and PHP leaks) and track if the scanner follows hidden canary tokens revealed inside those decoys.

```text
Incoming Request
       ↓
  normalizePath
       ↓
  matcherEngine (Exact O(1) → Prefix Trie → Suffix/Segment → Regex)
       ↓
  scoringEngine (Multi-signal confidence calculation 0-100)
       ↓
  actionExecutor (observe / allow / block / decoy / troll / silent)
       ↓
  sessionTracker & Decoy Lineage (Canary token interaction tracking)
```

---

## Features

* **⚡ Ultra-High Performance**: Over 120,000–200,000+ requests/sec with an average latency of ~5–8 microseconds.
* **🪶 Zero Dependencies**: Core runs anywhere with zero dependencies (Node.js, Cloudflare Workers, Deno, Bun).
* **🎭 Honeypot Decoy Engine**: Generates believable, completely safe fake `.env`, `.aws/credentials`, `/.ssh/id_rsa`, `wp-config.php`, `database.yml`, `.git/config`, `sftp-config.json`, and SQL backups.
* **🪐 Per-Scanner Fake Universe**: Deterministic pseudo-random generation ensures the same scanner always sees consistent fake hostnames, private RFC 1918 IPs, and database usernames.
* **🐤 Canary Tokens & Decoy Lineage**: Embeds unique tracking identifiers in fake decoys. If a scanner follows a revealed canary path, `tracefield` tracks the interaction and marks them as a confirmed scanner.
* **🪜 Progressive Absurdity Escalation Loop**: Troll mode can escalate step-by-step into hilarious rabbit holes (quantum databases, sentience crises, dungeon cat CTFs).
* **🧮 Multi-Signal Confidence Scoring**: Uses multi-category probing, rapid enumeration, path traversal, encoding depth, and decoy interactions to compute a 0–100 confidence score without relying solely on User-Agent.
* **🛡️ False-Positive Protection**: Whitelists common legitimate developer and documentation paths (e.g. `/.environment-guide`, `/assets/env.js`, `/blog/wordpress-history`, `/git/tutorial`).
* **🔌 Framework Adapters**: Built-in first-class middleware for **Express**, **Hono**, and **Cloudflare Workers**.
* **📊 Log Analyzer & CLI**: Built-in CLI (`tracefield analyze access.log`) powered by `cac` for forensic analysis of Nginx and Apache logs.

---

## Installation

```bash
# Install directly from GitHub (litepacks)
npm install github:litepacks/tracefield

# Or via npm
npm install @litepacks/tracefield
# or
npm install tracefield
```

---

## Quick Start

### 1. Express

```typescript
import express from 'express';
import { tracefield } from 'tracefield/express';

const app = express();

// Recommended production onboarding: start in 'observe' mode
app.use(tracefield({
  mode: 'observe'
}));

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(3000);
```

### 2. Hono

```typescript
import { Hono } from 'hono';
import { tracefield } from 'tracefield/hono';

const app = new Hono();

app.use('*', tracefield({
  mode: 'protect',
  action: 'decoy'
}));

app.get('/', (c) => c.text('Hello Hono!'));

export default app;
```

### 3. Cloudflare Workers

```typescript
import { tracefieldCloudflare } from 'tracefield/cloudflare';

export default {
  fetch: tracefieldCloudflare(async (request, env, ctx) => {
    return new Response('Hello from Cloudflare Worker!');
  }, {
    mode: 'protect',
    action: 'block',
    responseStatus: 404
  })
};
```

### 4. Direct Core Usage (Framework-Independent)

```typescript
import { inspect, createDetector } from 'tracefield';

const result = await inspect({
  path: '/.env.production',
  method: 'GET',
  headers: { 'user-agent': 'masscan/1.3' },
  ip: '198.51.100.12'
});

console.log(result);
/*
{
  matched: true,
  blocked: false,
  action: 'block',
  category: 'dotenv',
  rule: 'dotenv-exact-prod',
  severity: 'critical',
  confidence: 60,
  signals: ['known-sensitive-path', 'dotenv-probe', 'known-scanner-user-agent'],
  rawPath: '/.env.production',
  normalizedPath: '/.env.production'
}
*/

console.log(result.explain());
/*
Confidence: 60

+45  /.env.production matched rule dotenv-exact-prod (dotenv, critical)
+15  User-Agent contains automated scanner signature (masscan/1.3)
*/
```

---

## Detection Categories

`tracefield` includes precompiled rules covering 18+ distinct reconnaissance categories:

| Category | Examples |
| :--- | :--- |
| **`dotenv`** | `/.env`, `/.env.production`, `/.env.local`, `/storage/.env` |
| **`git`** | `/.git/config`, `/.git/HEAD`, `/.git/index` |
| **`secrets`** | `/.aws/credentials`, `/.ssh/id_rsa`, `/server.key`, `/sftp-config.json`, `/.netrc`, `/ftp.txt` |
| **`wordpress`** | `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`, `/wp-config.php.bak` |
| **`database`** | `/backup.sql`, `/database.sql`, `/config/database.yml`, `/db.sqlite3` |
| **`backups`** | `/site.zip`, `/www.tar.gz`, `/backup.tar.gz`, `.sql.gz` |
| **`php`** | `/phpinfo.php`, `/info.php`, `/phpmyadmin/`, `/adminer.php` |
| **`framework`** | `/vendor/phpunit/`, `/actuator/env`, `/application.properties` |
| **`path-traversal`**| `../../etc/passwd`, `..\..\win.ini`, double-encoded traversal |
| **`server-config`** | `/server-status`, `/.htaccess`, `/.htpasswd`, `/web.config`, `/nginx.conf` |
| **`cloud`** | `/latest/meta-data`, `/computeMetadata/v1` |
| **`shell`** | `/c99.php`, `/r57.php`, `/wso.php`, `/cmd.php`, `/alfa.php` |
| **`known-malware`** | `/HNAP1/`, `/setup.cgi`, `/boaform/admin/formLogin` |

---

## Honeypot Decoy Engine & Canary Lineage

When `action: 'decoy'` is enabled, `tracefield` returns realistic synthetic configurations:

```env
# Environment Configuration - AcmeProduction
APP_NAME=AcmeProduction
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:tracefield_fake_key_8df921=
DB_HOST=10.24.8.12
DB_PORT=5432
DB_DATABASE=prod_main
DB_USERNAME=app_prod
DB_PASSWORD=tracefield_fake_db_8df921

INTERNAL_API_KEY=tracefield_decoy_d_7fa912
BACKUP_ARCHIVE_PATH=/internal/backups/d_7fa912/prod.sql
```

### Canary Follow-up Detection

If the scanner subsequently requests `/internal/backups/d_7fa912/prod.sql`, `tracefield`:
1. Recognizes the canary token `d_7fa912`.
2. Emits a `decoy.followed` event.
3. Automatically escalates scanner confidence to **`confirmed (90+)`**.
4. Tracks decoy lineage up to `maxDepth` (default: 3) to prevent infinite loops.

---

## Configuration Options

```typescript
tracefield({
  // 'observe': Detect, score and emit events without blocking
  // 'protect': Enforce configured actions (block, decoy, troll, silent)
  mode: 'observe',

  // Default action when a probe is detected
  action: 'block', // 'block' | 'decoy' | 'troll' | 'silent' | 'allow'

  // HTTP status for blocked responses (404 or 403)
  responseStatus: 404,

  // Override actions per category
  actions: {
    dotenv: 'decoy',
    secrets: 'decoy',
    wordpress: 'block',
    'path-traversal': 'block'
  },

  // Decoy options
  decoy: {
    enabled: true,
    perScanner: true, // Same scanner receives consistent fake details
    maxDepth: 3       // Maximum canary recursion depth
  },

  // Troll options (for humorous safe responses)
  troll: {
    loop: true, // Enable Progressive Absurdity Escalation Loop
    type: 'loop' // 'loop' | 'rsa-troll' | 'fake-jwt' | 'tarpit' | 'fake-graphql' | 'php-leak' | 'php-error' | 'ftp-leak' | 'teapot' | 'fake-error' | 'rickroll' | 'empty-200'
  },

  // Scoring thresholds
  scoring: {
    suspicious: 40,
    scanner: 70,
    confirmed: 90
  },

  // Session & privacy tracking
  tracking: {
    enabled: true,
    ttl: '15m',
    maxSessions: 5000,
    maskIp: true // Automatically masks IPv4 to /24 and IPv6 to /48
  },

  // Custom rules
  rules: [
    {
      id: 'custom-internal-backup',
      category: 'custom',
      severity: 'high',
      path: '/old-backup'
    }
  ]
});
```

---

## CLI & Log Analyzer

Analyze access logs using the `tracefield` CLI:

```bash
# Run directly via GitHub npx
npx github:litepacks/tracefield analyze access.log
npx github:litepacks/tracefield test-path "/.env.production"

# Or if installed locally
npx tracefield analyze access.log
npx tracefield analyze access.log --json
npx tracefield test-path "/.env.production"
```

Example CLI Output:

```text
Requests analyzed: 98,312
Probe requests:    4,821
Likely scanners:   142
Confirmed scanners: 38

Top categories:
  dotenv              1,202
  wordpress             981
  git                   491
  backups               421
```

---

## Benchmarks

Run benchmarks locally:

```bash
npm run bench
```

Results (Apple M-series, Node.js v24):

```text
| Scenario                             | Throughput     | Avg Latency | p50 Latency | p95 Latency |
|--------------------------------------|----------------|-------------|-------------|-------------|
| 1. Normal Safe Request (/api/items)  | 169,279 ops/s  | 5.83 µs     | 5.00 µs     | 8.08 µs     |
| 2. Exact Malicious (/.env.prod)      | 201,990 ops/s  | 4.89 µs     | 4.29 µs     | 6.62 µs     |
| 3. Prefix Probe (/wp-admin/...)      | 170,159 ops/s  | 5.82 µs     | 5.42 µs     | 6.79 µs     |
| 4. Suffix Probe (/backup.sql.gz)     | 177,206 ops/s  | 5.58 µs     | 5.13 µs     | 7.37 µs     |
| 5. Double-encoded Traversal          | 179,655 ops/s  | 5.51 µs     | 4.83 µs     | 7.63 µs     |
| 6. Active Scanner Session (Tracked)  | 196,362 ops/s  | 5.04 µs     | 4.46 µs     | 6.96 µs     |
```

---

## Safety & Privacy Constraints

* **Strict Isolation**: `tracefield` never reads real environment variables, local `.env` files, or application secrets.
* **Safe Fake Namespaces**: Decoy credentials use clear internal markers (`tracefield_fake_...`, `tracefield_decoy_...`), RFC 1918 private IPs (`10.x.x.x`), and safe reserved TLDs (`.test`, `.invalid`, `example.com`).
* **Privacy by Default**: IP addresses are masked (`192.168.1.0/24`) to protect personal data under GDPR/CCPA.
* **Non-Destructive**: `tracefield` never attacks or floods scanners and does not perform slow-loris or resource exhaustion attacks.

---

## License

MIT © 2026 [litepacks](https://github.com/litepacks)
