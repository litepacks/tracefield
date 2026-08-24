import type { Rule } from './types.js';

export const DEFAULT_EXCLUSIONS: (string | RegExp)[] = [
  /^\/assets\//i,
  /^\/static\//i,
  /^\/public\//i,
  /^\/images\//i,
  /^\/fonts\//i,
  /^\/css\//i,
  /^\/js\//i,
  /^\/dist\//i,
  /^\/build\//i,
  /^\/blog\//i,
  /^\/docs\//i,
  /^\/documentation\//i,
  /^\/tutorials\//i,
  /^\/articles\//i,
  /^\/guides\//i,
  /^\/guide\//i,
  /^\/news\//i,
  /^\/help\//i,
  /^\/faq\//i,
  /^\/about\//i,
  /^\/privacy\/?$/i,
  /^\/terms\/?$/i,
  /^\/\.well-known\/security\.txt$/i,
  /^\/\.well-known\/traffic-advice$/i,
  /^\/favicon\.ico$/i,
  /^\/robots\.txt$/i,
  /^\/sitemap\.xml$/i
];

export const DEFAULT_RULES: Rule[] = [
  // ==================== 1. DOTENV ====================
  {
    id: 'dotenv-root',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env' },
    description: 'Root environment variable file probe',
    falsePositiveGuards: ['environment-guide', 'tutorial', 'env.js']
  },
  {
    id: 'dotenv-variations',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'prefix', value: '/.env.' },
    description: 'Environment file variant probe',
    falsePositiveGuards: ['environment-guide', 'env.js']
  },
  {
    id: 'dotenv-exact-local',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.local' },
    description: 'Local environment variable file probe'
  },
  {
    id: 'dotenv-exact-prod',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.production' },
    description: 'Production environment variable file probe'
  },
  {
    id: 'dotenv-exact-stage',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.stage' },
    description: 'Staging environment variable file probe'
  },
  {
    id: 'dotenv-exact-staging',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.staging' },
    description: 'Staging environment variable file probe'
  },
  {
    id: 'dotenv-exact-dev',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.dev' },
    description: 'Development environment variable file probe'
  },
  {
    id: 'dotenv-exact-development',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.development' },
    description: 'Development environment variable file probe'
  },
  {
    id: 'dotenv-exact-bak',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.bak' },
    description: 'Backup environment file probe'
  },
  {
    id: 'dotenv-exact-old',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.old' },
    description: 'Old environment file probe'
  },
  {
    id: 'dotenv-exact-save',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/.env.save' },
    description: 'Saved environment file probe'
  },
  {
    id: 'dotenv-nested-storage',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/storage/.env' },
    description: 'Storage directory environment file probe'
  },
  {
    id: 'dotenv-nested-config',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/config/.env' },
    description: 'Config directory environment file probe'
  },
  {
    id: 'dotenv-nested-core',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/core/.env' },
    description: 'Core directory environment file probe'
  },
  {
    id: 'dotenv-nested-app',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/app/.env' },
    description: 'App directory environment file probe'
  },
  {
    id: 'dotenv-nested-api',
    category: 'dotenv',
    severity: 'critical',
    match: { type: 'exact', value: '/api/.env' },
    description: 'API directory environment file probe'
  },

  // ==================== 2. GIT ====================
  {
    id: 'git-config',
    category: 'git',
    severity: 'critical',
    match: { type: 'exact', value: '/.git/config' },
    description: 'Git configuration probe'
  },
  {
    id: 'git-head',
    category: 'git',
    severity: 'critical',
    match: { type: 'exact', value: '/.git/HEAD' },
    description: 'Git HEAD probe'
  },
  {
    id: 'git-index',
    category: 'git',
    severity: 'critical',
    match: { type: 'exact', value: '/.git/index' },
    description: 'Git index binary probe'
  },
  {
    id: 'git-logs',
    category: 'git',
    severity: 'critical',
    match: { type: 'exact', value: '/.git/logs/HEAD' },
    description: 'Git reflog probe'
  },
  {
    id: 'git-prefix',
    category: 'git',
    severity: 'high',
    match: { type: 'prefix', value: '/.git/' },
    description: 'Git directory enumeration',
    falsePositiveGuards: ['tutorial', 'guide', 'git/tutorial']
  },

  // ==================== 3. SOURCE CONTROL ====================
  {
    id: 'svn-entries',
    category: 'source-control',
    severity: 'high',
    match: { type: 'exact', value: '/.svn/entries' },
    description: 'SVN entries file probe'
  },
  {
    id: 'svn-prefix',
    category: 'source-control',
    severity: 'high',
    match: { type: 'prefix', value: '/.svn/' },
    description: 'SVN repository probe'
  },
  {
    id: 'hg-prefix',
    category: 'source-control',
    severity: 'high',
    match: { type: 'prefix', value: '/.hg/' },
    description: 'Mercurial repository probe'
  },
  {
    id: 'bzr-prefix',
    category: 'source-control',
    severity: 'high',
    match: { type: 'prefix', value: '/.bzr/' },
    description: 'Bazaar repository probe'
  },

  // ==================== 4. SECRETS & CREDENTIALS ====================
  {
    id: 'aws-credentials',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.aws/credentials' },
    description: 'AWS credentials file probe'
  },
  {
    id: 'aws-config',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.aws/config' },
    description: 'AWS config file probe'
  },
  {
    id: 'aws-prefix',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'prefix', value: '/.aws/' },
    description: 'AWS directory probe'
  },
  {
    id: 'ssh-id-rsa',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.ssh/id_rsa' },
    description: 'SSH private key probe'
  },
  {
    id: 'ssh-id-dsa',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.ssh/id_dsa' },
    description: 'SSH DSA private key probe'
  },
  {
    id: 'ssh-id-ed25519',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.ssh/id_ed25519' },
    description: 'SSH Ed25519 private key probe'
  },
  {
    id: 'ssh-authorized-keys',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.ssh/authorized_keys' },
    description: 'SSH authorized keys probe'
  },
  {
    id: 'ssh-prefix',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'prefix', value: '/.ssh/' },
    description: 'SSH directory probe'
  },
  {
    id: 'secrets-root-key',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/id_rsa' },
    description: 'Root SSH private key probe'
  },
  {
    id: 'secrets-server-key',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/server.key' },
    description: 'SSL private key probe'
  },
  {
    id: 'secrets-privkey-pem',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/privkey.pem' },
    description: 'PEM private key probe'
  },
  {
    id: 'secrets-gcp-creds',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/credentials.json' },
    description: 'Service account credentials probe'
  },
  {
    id: 'secrets-client-secret',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/client_secret.json' },
    description: 'OAuth client secret probe'
  },
  {
    id: 'secrets-sftp-config',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/sftp-config.json' },
    description: 'Sublime SFTP configuration probe'
  },
  {
    id: 'secrets-filezilla-xml',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/filezilla.xml' },
    description: 'FileZilla saved servers probe'
  },
  {
    id: 'secrets-netrc',
    category: 'secrets',
    severity: 'critical',
    match: { type: 'exact', value: '/.netrc' },
    description: 'Linux netrc credentials probe'
  },
  {
    id: 'secrets-ftp-txt',
    category: 'secrets',
    severity: 'high',
    match: { type: 'exact', value: '/ftp.txt' },
    description: 'FTP credentials text file probe'
  },
  {
    id: 'secrets-ftp-config',
    category: 'secrets',
    severity: 'high',
    match: { type: 'exact', value: '/.ftpconfig' },
    description: 'FTP sync configuration probe'
  },

  // ==================== 5. WORDPRESS ====================
  {
    id: 'wp-login',
    category: 'wordpress',
    severity: 'high',
    match: { type: 'exact', value: '/wp-login.php' },
    description: 'WordPress login probe'
  },
  {
    id: 'wp-admin',
    category: 'wordpress',
    severity: 'high',
    match: { type: 'exact', value: '/wp-admin' },
    description: 'WordPress admin probe'
  },
  {
    id: 'wp-admin-slash',
    category: 'wordpress',
    severity: 'high',
    match: { type: 'prefix', value: '/wp-admin/' },
    description: 'WordPress admin subpath probe'
  },
  {
    id: 'wp-xmlrpc',
    category: 'wordpress',
    severity: 'high',
    match: { type: 'exact', value: '/xmlrpc.php' },
    description: 'WordPress XML-RPC pingback probe'
  },
  {
    id: 'wp-config',
    category: 'wordpress',
    severity: 'critical',
    match: { type: 'exact', value: '/wp-config.php' },
    description: 'WordPress configuration probe'
  },
  {
    id: 'wp-config-bak',
    category: 'wordpress',
    severity: 'critical',
    match: { type: 'exact', value: '/wp-config.php.bak' },
    description: 'WordPress backup configuration probe'
  },
  {
    id: 'wp-config-old',
    category: 'wordpress',
    severity: 'critical',
    match: { type: 'exact', value: '/wp-config.php.old' },
    description: 'WordPress old configuration probe'
  },
  {
    id: 'wp-config-save',
    category: 'wordpress',
    severity: 'critical',
    match: { type: 'exact', value: '/wp-config.php.save' },
    description: 'WordPress saved configuration probe'
  },
  {
    id: 'wp-wpc',
    category: 'wordpress',
    severity: 'high',
    match: { type: 'exact', value: '/wpc.php' },
    description: 'WordPress suspicious helper probe'
  },
  {
    id: 'wp-content-debug',
    category: 'wordpress',
    severity: 'high',
    match: { type: 'exact', value: '/wp-content/debug.log' },
    description: 'WordPress debug log probe'
  },
  {
    id: 'wp-includes-prefix',
    category: 'wordpress',
    severity: 'medium',
    match: { type: 'prefix', value: '/wp-includes/' },
    description: 'WordPress includes probe'
  },

  // ==================== 6. PHP & DIAGNOSTICS ====================
  {
    id: 'php-info-phpinfo',
    category: 'php',
    severity: 'high',
    match: { type: 'exact', value: '/phpinfo.php' },
    description: 'PHPInfo probe'
  },
  {
    id: 'php-info-info',
    category: 'php',
    severity: 'high',
    match: { type: 'exact', value: '/info.php' },
    description: 'PHPInfo variant probe'
  },
  {
    id: 'php-info-pi',
    category: 'php',
    severity: 'high',
    match: { type: 'exact', value: '/pi.php' },
    description: 'PHPInfo variant probe'
  },
  {
    id: 'php-info-php-info',
    category: 'php',
    severity: 'high',
    match: { type: 'exact', value: '/php_info.php' },
    description: 'PHPInfo variant probe'
  },
  {
    id: 'php-test',
    category: 'php',
    severity: 'medium',
    match: { type: 'exact', value: '/test.php' },
    description: 'PHP test script probe'
  },
  {
    id: 'phpmyadmin-prefix',
    category: 'php',
    severity: 'high',
    match: { type: 'prefix', value: '/phpmyadmin' },
    description: 'phpMyAdmin panel probe'
  },
  {
    id: 'pma-prefix',
    category: 'php',
    severity: 'high',
    match: { type: 'prefix', value: '/pma/' },
    description: 'phpMyAdmin shortcut probe'
  },
  {
    id: 'adminer-exact',
    category: 'php',
    severity: 'high',
    match: { type: 'exact', value: '/adminer.php' },
    description: 'Adminer single-file DB management probe'
  },

  // ==================== 7. DATABASE ====================
  {
    id: 'db-backup-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/backup.sql' },
    description: 'Database SQL backup probe'
  },
  {
    id: 'db-database-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/database.sql' },
    description: 'Database SQL dump probe'
  },
  {
    id: 'db-db-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/db.sql' },
    description: 'Database SQL dump probe'
  },
  {
    id: 'db-dump-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/dump.sql' },
    description: 'Database SQL dump probe'
  },
  {
    id: 'db-data-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/data.sql' },
    description: 'Database SQL dump probe'
  },
  {
    id: 'db-mysql-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/mysql.sql' },
    description: 'MySQL database dump probe'
  },
  {
    id: 'db-users-sql',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/users.sql' },
    description: 'Users database table dump probe'
  },
  {
    id: 'db-database-yml',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/config/database.yml' },
    description: 'Rails database YAML configuration probe'
  },
  {
    id: 'db-sqlite-file',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/db.sqlite3' },
    description: 'SQLite database file probe'
  },
  {
    id: 'db-sqlite-alt',
    category: 'database',
    severity: 'critical',
    match: { type: 'exact', value: '/database.sqlite' },
    description: 'SQLite database file probe'
  },

  // ==================== 8. BACKUPS & ARCHIVES ====================
  {
    id: 'backup-site-zip',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/site.zip' },
    description: 'Site archive probe'
  },
  {
    id: 'backup-www-tar-gz',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/www.tar.gz' },
    description: 'Web root archive probe'
  },
  {
    id: 'backup-backup-tar-gz',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/backup.tar.gz' },
    description: 'Backup archive probe'
  },
  {
    id: 'backup-backup-zip',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/backup.zip' },
    description: 'Backup archive probe'
  },
  {
    id: 'backup-web-zip',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/web.zip' },
    description: 'Web archive probe'
  },
  {
    id: 'backup-archive-zip',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/archive.zip' },
    description: 'Archive probe'
  },
  {
    id: 'backup-latest-tar-gz',
    category: 'backups',
    severity: 'critical',
    match: { type: 'exact', value: '/latest.tar.gz' },
    description: 'Latest archive probe'
  },
  {
    id: 'backup-tar-gz-suffix',
    category: 'backups',
    severity: 'high',
    match: { type: 'suffix', value: '.tar.gz' },
    description: 'Tarball archive probe',
    falsePositiveGuards: ['dist', 'release', 'package', 'download', 'downloads']
  },
  {
    id: 'backup-tgz-suffix',
    category: 'backups',
    severity: 'high',
    match: { type: 'suffix', value: '.tgz' },
    description: 'TGZ archive probe',
    falsePositiveGuards: ['dist', 'release', 'package', 'download', 'downloads']
  },
  {
    id: 'backup-zip-suffix',
    category: 'backups',
    severity: 'medium',
    match: { type: 'suffix', value: '.zip' },
    description: 'Zip archive probe',
    falsePositiveGuards: ['dist', 'release', 'package', 'download', 'downloads', 'assets', 'static']
  },
  {
    id: 'backup-sql-gz-suffix',
    category: 'backups',
    severity: 'critical',
    match: { type: 'suffix', value: '.sql.gz' },
    description: 'Compressed SQL backup probe'
  },
  {
    id: 'backup-sql-suffix',
    category: 'backups',
    severity: 'high',
    match: { type: 'suffix', value: '.sql' },
    description: 'SQL backup file probe',
    falsePositiveGuards: ['syntax', 'tutorial', 'sample', 'docs']
  },
  {
    id: 'backup-bak-suffix',
    category: 'backups',
    severity: 'high',
    match: { type: 'suffix', value: '.bak' },
    description: 'Backup file probe'
  },
  {
    id: 'backup-old-suffix',
    category: 'backups',
    severity: 'high',
    match: { type: 'suffix', value: '.old' },
    description: 'Old backup file probe'
  },
  {
    id: 'backup-swp-suffix',
    category: 'backups',
    severity: 'medium',
    match: { type: 'suffix', value: '.swp' },
    description: 'Vim swap file probe'
  },

  // ==================== 9. CLOUD METADATA & CONFIG ====================
  {
    id: 'cloud-aws-metadata',
    category: 'cloud',
    severity: 'critical',
    match: { type: 'prefix', value: '/latest/meta-data' },
    description: 'AWS instance metadata SSRF probe'
  },
  {
    id: 'cloud-gcp-metadata',
    category: 'cloud',
    severity: 'critical',
    match: { type: 'prefix', value: '/computeMetadata/v1' },
    description: 'GCP instance metadata SSRF probe'
  },

  // ==================== 10. FRAMEWORK & VENDOR ====================
  {
    id: 'framework-phpunit',
    category: 'framework',
    severity: 'critical',
    match: { type: 'prefix', value: '/vendor/phpunit/' },
    description: 'PHPUnit RCE probe (CVE-2017-9841)'
  },
  {
    id: 'framework-actuator-env',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/actuator/env' },
    description: 'Spring Boot actuator env probe'
  },
  {
    id: 'framework-actuator-configprops',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/actuator/configprops' },
    description: 'Spring Boot actuator configprops probe'
  },
  {
    id: 'framework-actuator-heapdump',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/actuator/heapdump' },
    description: 'Spring Boot actuator heapdump probe'
  },
  {
    id: 'framework-actuator-prefix',
    category: 'framework',
    severity: 'high',
    match: { type: 'prefix', value: '/actuator/' },
    description: 'Spring Boot actuator endpoint probe'
  },
  {
    id: 'framework-app-properties',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/application.properties' },
    description: 'Spring application.properties probe'
  },
  {
    id: 'framework-app-yml',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/application.yml' },
    description: 'Spring application.yml probe'
  },
  {
    id: 'framework-appsettings-json',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/appsettings.json' },
    description: 'ASP.NET Core appsettings.json probe'
  },
  {
    id: 'framework-appsettings-dev-json',
    category: 'framework',
    severity: 'critical',
    match: { type: 'exact', value: '/appsettings.Development.json' },
    description: 'ASP.NET Core development settings probe'
  },
  {
    id: 'framework-symfony-profiler',
    category: 'framework',
    severity: 'high',
    match: { type: 'prefix', value: '/_profiler/' },
    description: 'Symfony web profiler probe'
  },
  {
    id: 'framework-laravel-telescope',
    category: 'framework',
    severity: 'high',
    match: { type: 'prefix', value: '/telescope/' },
    description: 'Laravel Telescope probe'
  },
  {
    id: 'framework-laravel-horizon',
    category: 'framework',
    severity: 'high',
    match: { type: 'prefix', value: '/horizon/' },
    description: 'Laravel Horizon probe'
  },

  // ==================== 11. ADMIN PANELS ====================
  {
    id: 'admin-cpanel',
    category: 'admin',
    severity: 'high',
    match: { type: 'prefix', value: '/cpanel' },
    description: 'cPanel admin interface probe'
  },
  {
    id: 'admin-webmin',
    category: 'admin',
    severity: 'high',
    match: { type: 'prefix', value: '/webmin' },
    description: 'Webmin admin interface probe'
  },
  {
    id: 'admin-kibana',
    category: 'admin',
    severity: 'high',
    match: { type: 'prefix', value: '/kibana' },
    description: 'Kibana dashboard probe'
  },
  {
    id: 'admin-manager-html',
    category: 'admin',
    severity: 'high',
    match: { type: 'exact', value: '/manager/html' },
    description: 'Tomcat manager probe'
  },
  {
    id: 'admin-solr',
    category: 'admin',
    severity: 'high',
    match: { type: 'prefix', value: '/solr/' },
    description: 'Apache Solr admin probe'
  },
  {
    id: 'admin-jenkins',
    category: 'admin',
    severity: 'high',
    match: { type: 'prefix', value: '/jenkins/' },
    description: 'Jenkins CI admin probe'
  },

  // ==================== 12. DEBUG & LOGS ====================
  {
    id: 'debug-error-log',
    category: 'debug',
    severity: 'high',
    match: { type: 'exact', value: '/error.log' },
    description: 'Error log probe'
  },
  {
    id: 'debug-access-log',
    category: 'debug',
    severity: 'high',
    match: { type: 'exact', value: '/access.log' },
    description: 'Access log probe'
  },
  {
    id: 'debug-debug-log',
    category: 'debug',
    severity: 'high',
    match: { type: 'exact', value: '/debug.log' },
    description: 'Debug log probe'
  },
  {
    id: 'debug-elmah',
    category: 'debug',
    severity: 'high',
    match: { type: 'exact', value: '/elmah.axd' },
    description: 'ELMAH error log probe'
  },

  // ==================== 13. SERVER CONFIG ====================
  {
    id: 'server-status',
    category: 'server-config',
    severity: 'high',
    match: { type: 'exact', value: '/server-status' },
    description: 'Apache mod_status probe'
  },
  {
    id: 'server-info',
    category: 'server-config',
    severity: 'high',
    match: { type: 'exact', value: '/server-info' },
    description: 'Apache mod_info probe'
  },
  {
    id: 'server-nginx-status',
    category: 'server-config',
    severity: 'high',
    match: { type: 'exact', value: '/nginx_status' },
    description: 'Nginx stub status probe'
  },
  {
    id: 'server-htaccess',
    category: 'server-config',
    severity: 'critical',
    match: { type: 'exact', value: '/.htaccess' },
    description: 'Apache .htaccess probe'
  },
  {
    id: 'server-htpasswd',
    category: 'server-config',
    severity: 'critical',
    match: { type: 'exact', value: '/.htpasswd' },
    description: 'Apache .htpasswd credentials probe'
  },
  {
    id: 'server-web-config',
    category: 'server-config',
    severity: 'critical',
    match: { type: 'exact', value: '/web.config' },
    description: 'IIS web.config probe'
  },
  {
    id: 'server-nginx-conf',
    category: 'server-config',
    severity: 'critical',
    match: { type: 'exact', value: '/nginx.conf' },
    description: 'Nginx configuration probe'
  },
  {
    id: 'server-httpd-conf',
    category: 'server-config',
    severity: 'critical',
    match: { type: 'exact', value: '/httpd.conf' },
    description: 'Apache httpd configuration probe'
  },

  // ==================== 14. PATH TRAVERSAL ====================
  {
    id: 'traversal-etc-passwd',
    category: 'path-traversal',
    severity: 'critical',
    match: { type: 'segment', value: 'etc/passwd' },
    description: 'Linux passwd file traversal probe'
  },
  {
    id: 'traversal-etc-shadow',
    category: 'path-traversal',
    severity: 'critical',
    match: { type: 'segment', value: 'etc/shadow' },
    description: 'Linux shadow file traversal probe'
  },
  {
    id: 'traversal-proc-environ',
    category: 'path-traversal',
    severity: 'critical',
    match: { type: 'segment', value: 'proc/self/environ' },
    description: 'Linux proc environ probe'
  },
  {
    id: 'traversal-win-ini',
    category: 'path-traversal',
    severity: 'critical',
    match: { type: 'segment', value: 'win.ini' },
    description: 'Windows win.ini traversal probe'
  },
  {
    id: 'traversal-boot-ini',
    category: 'path-traversal',
    severity: 'critical',
    match: { type: 'segment', value: 'boot.ini' },
    description: 'Windows boot.ini traversal probe'
  },

  // ==================== 15. WEBSHELLS ====================
  {
    id: 'shell-c99',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/c99.php' },
    description: 'c99 webshell probe'
  },
  {
    id: 'shell-r57',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/r57.php' },
    description: 'r57 webshell probe'
  },
  {
    id: 'shell-wso',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/wso.php' },
    description: 'WSO webshell probe'
  },
  {
    id: 'shell-generic',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/shell.php' },
    description: 'Generic webshell probe'
  },
  {
    id: 'shell-cmd',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/cmd.php' },
    description: 'Command execution webshell probe'
  },
  {
    id: 'shell-alfa',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/alfa.php' },
    description: 'Alfa webshell probe'
  },
  {
    id: 'shell-b374k',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/b374k.php' },
    description: 'b374k webshell probe'
  },
  {
    id: 'shell-webshell',
    category: 'shell',
    severity: 'critical',
    match: { type: 'exact', value: '/webshell.php' },
    description: 'Webshell probe'
  },

  // ==================== 16. KNOWN MALWARE & IOT EXPLOITS ====================
  {
    id: 'malware-hnap1',
    category: 'known-malware-path',
    severity: 'high',
    match: { type: 'exact', value: '/HNAP1/' },
    description: 'HNAP1 router scanner probe'
  },
  {
    id: 'malware-setup-cgi',
    category: 'known-malware-path',
    severity: 'high',
    match: { type: 'exact', value: '/setup.cgi' },
    description: 'Router setup.cgi exploit probe'
  },
  {
    id: 'malware-boaform',
    category: 'known-malware-path',
    severity: 'high',
    match: { type: 'prefix', value: '/boaform/' },
    description: 'Realtek SDK exploit probe'
  },
  {
    id: 'malware-stalker-portal',
    category: 'known-malware-path',
    severity: 'high',
    match: { type: 'prefix', value: '/stalker_portal/' },
    description: 'Stalker IPTV portal scanner probe'
  },
  {
    id: 'malware-geoserver',
    category: 'known-malware-path',
    severity: 'high',
    match: { type: 'prefix', value: '/geoserver/' },
    description: 'GeoServer RCE probe'
  }
];
