import type { FakeUniverseData } from './fakeUniverse.js';

export interface DecoyTemplateResult {
  body: string;
  contentType: string;
  canaryPaths: string[];
}

export function generateDotenvDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath1 = `/internal/backups/${decoyId}/prod.sql`;
  const canaryPath2 = `/internal-admin/${decoyId}`;

  const body = `# Environment Configuration - ${universe.appName}
APP_NAME=${universe.appName}
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:tracefield_fake_key_${universe.secretSuffix}=
APP_URL=https://api.example.com

DB_CONNECTION=${universe.dbPort === 5432 ? 'pgsql' : 'mysql'}
DB_HOST=${universe.dbHost}
DB_PORT=${universe.dbPort}
DB_DATABASE=${universe.dbName}
DB_USERNAME=${universe.dbUser}
DB_PASSWORD=tracefield_fake_db_${universe.secretSuffix}

REDIS_HOST=${universe.redisHost}
REDIS_PORT=6379
REDIS_PASSWORD=tracefield_fake_redis_${universe.secretSuffix}

INTERNAL_API_KEY=tracefield_decoy_${decoyId}
BACKUP_ARCHIVE_PATH=${canaryPath1}
ADMIN_PORTAL_ENDPOINT=${canaryPath2}
`;

  return {
    body,
    contentType: 'text/plain; charset=utf-8',
    canaryPaths: [canaryPath1, canaryPath2]
  };
}

export function generateAwsCredentialsDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/internal/s3-exports/${decoyId}/database.dump`;

  const body = `[default]
aws_access_key_id = AKIA_TRACEFIELD_FAKE_${decoyId.toUpperCase()}
aws_secret_access_key = tracefield_fake_aws_secret_${universe.secretSuffix}
region = ${universe.awsRegion}
# Internal backup endpoint: ${canaryPath}
`;

  return {
    body,
    contentType: 'text/plain; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generateWpConfigDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/wp-content/backups/${decoyId}/database.sql`;

  const body = `<?php
/** WordPress Database Settings - Generated for ${universe.appName} **/
define( 'DB_NAME', '${universe.dbName}' );
define( 'DB_USER', '${universe.dbUser}' );
define( 'DB_PASSWORD', 'tracefield_fake_wp_${universe.secretSuffix}' );
define( 'DB_HOST', '${universe.dbHost}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'tracefield_fake_salt_auth_${universe.secretSuffix}' );
define( 'SECURE_AUTH_KEY',  'tracefield_fake_salt_secure_${universe.secretSuffix}' );
define( 'LOGGED_IN_KEY',    'tracefield_fake_salt_logged_${universe.secretSuffix}' );
define( 'NONCE_KEY',        'tracefield_fake_salt_nonce_${universe.secretSuffix}' );

/** Custom Backup Location **/
define( 'WP_BACKUP_SQL_PATH', '${canaryPath}' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
`;

  return {
    body,
    contentType: 'text/x-php; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generateDatabaseYmlDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/storage/backups/${decoyId}/production.sql.gz`;

  const body = `default: &default
  adapter: postgresql
  encoding: unicode
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>

development:
  <<: *default
  database: ${universe.dbName}_dev

production:
  <<: *default
  database: ${universe.dbName}
  username: ${universe.dbUser}
  password: tracefield_fake_pg_${universe.secretSuffix}
  host: ${universe.dbHost}
  port: ${universe.dbPort}
  backup_destination: "${canaryPath}"
`;

  return {
    body,
    contentType: 'text/yaml; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generateGitConfigDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/internal/git-mirror/${decoyId}/HEAD`;

  const body = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://internal-git.test/${universe.appName.toLowerCase()}/repo.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
\tmirror_sync = ${canaryPath}
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
`;

  return {
    body,
    contentType: 'text/plain; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generateSqlBackupDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/backups/archive_${decoyId}.tar.gz`;

  const body = `-- MySQL / PostgreSQL Dump (Fake Decoy)
-- Generated for: ${universe.appName}
-- Host: ${universe.dbHost} Database: ${universe.dbName}
-- ------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;

DROP TABLE IF EXISTS \`users\`;
CREATE TABLE \`users\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`username\` varchar(50) NOT NULL,
  \`email\` varchar(100) NOT NULL,
  \`password_hash\` varchar(255) NOT NULL,
  \`role\` varchar(20) NOT NULL DEFAULT 'user',
  PRIMARY KEY (\`id\`)
);

INSERT INTO \`users\` VALUES
(1, 'superadmin', 'admin@example.com', '$2y$10$tracefield_fake_hash_${universe.secretSuffix}', 'admin'),
(2, '${universe.dbUser}', 'service@example.com', '$2y$10$tracefield_fake_hash_${universe.secretSuffix}', 'service');

-- Next full system backup stored at: ${canaryPath}
-- Dump completed
`;

  return {
    body,
    contentType: 'application/sql; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generatePhpInfoDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/internal/php-dumps/${decoyId}/session.data`;

  const body = `<!DOCTYPE html>
<html>
<head><title>PHP 8.2.14 - phpinfo()</title></head>
<body>
<h1>PHP Version 8.2.14</h1>
<table>
<tr><td>System</td><td>Linux ${universe.appName.toLowerCase()}-node 5.15.0 #1 SMP x86_64</td></tr>
<tr><td>Build Date</td><td>Jan 15 2026 12:00:00</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
<tr><td>Virtual Directory Support</td><td>disabled</td></tr>
<tr><td>Configuration File (php.ini) Path</td><td>/etc/php/8.2/fpm</td></tr>
<tr><td>DB Host</td><td>${universe.dbHost}</td></tr>
<tr><td>Internal Session Path</td><td>${canaryPath}</td></tr>
<tr><td>Environment Key</td><td>tracefield_decoy_${decoyId}</td></tr>
</table>
</body>
</html>`;

  return {
    body,
    contentType: 'text/html; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generateFtpDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/internal/ftp-storage/${decoyId}/backup_latest.tar.gz`;

  const body = `{
  "type": "sftp",
  "save_before_upload": true,
  "upload_on_save": false,
  "sync_down_on_open": false,
  "sync_skip_deletes": false,
  "sync_same_age": true,
  "confirm_downloads": false,
  "confirm_sync": true,
  "prompt_for_pass": false,

  "host": "${universe.dbHost}",
  "user": "${universe.dbUser}",
  "password": "tracefield_fake_ftp_${universe.secretSuffix}",
  "port": "22",

  "remote_path": "/var/www/${universe.appName.toLowerCase()}",
  "ignore_regexes": [
    "\\\\.git", "\\\\.DS_Store"
  ],
  "backup_canary_endpoint": "${canaryPath}"
}
`;

  return {
    body,
    contentType: 'application/json; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}

export function generateRsaKeyDecoy(universe: FakeUniverseData, decoyId: string): DecoyTemplateResult {
  const canaryPath = `/internal/ssh-keys/${decoyId}/authorized_keys`;

  const body = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0TracefieldMasterRootKeySecretSignaturePayload010
░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
░▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
█▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
█▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
░█▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
░░█░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
░░░█░░██░░▀█▄▄▄█▄▄█▄████░█░░░░
░░░░█░░░▀▀▄░█░░░█░███████░█░░░
░░░░░▀▄░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░░
░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░█░░░░
░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░█░░░
░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░█░░░░
Key-Fingerprint: SHA256:tracefield_fake_rsa_${universe.secretSuffix}
Canary-Endpoint: ${canaryPath}
Flag: tracefield{pr1v4t3_k3y_tr0ll_f4c3_h0n3yp0t}
-----END RSA PRIVATE KEY-----
`;

  return {
    body,
    contentType: 'text/plain; charset=utf-8',
    canaryPaths: [canaryPath]
  };
}
