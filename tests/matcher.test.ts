import { describe, expect, it } from 'vitest';
import { compileRules } from '../src/rules/compiler.js';
import { MatcherEngine } from '../src/matcher/index.js';
import { normalizePath } from '../src/normalizer/index.js';

describe('Matcher Engine', () => {
  const ruleset = compileRules();
  const matcher = new MatcherEngine(ruleset);

  it('matches exact sensitive files', () => {
    const paths = [
      '/.env',
      '/.env.production',
      '/.git/config',
      '/.git/HEAD',
      '/wp-login.php',
      '/xmlrpc.php',
      '/.aws/credentials',
      '/phpinfo.php',
      '/config/database.yml',
      '/application.properties'
    ];

    for (const p of paths) {
      const norm = normalizePath(p);
      const res = matcher.match(norm);
      expect(res.matched, `Expected match for ${p}`).toBe(true);
      expect(res.rule).toBeDefined();
    }
  });

  it('matches prefix sensitive paths', () => {
    const paths = [
      '/.env.custom_stage',
      '/.git/objects/abc',
      '/wp-admin/includes/file.php',
      '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
      '/actuator/env'
    ];

    for (const p of paths) {
      const norm = normalizePath(p);
      const res = matcher.match(norm);
      expect(res.matched, `Expected prefix match for ${p}`).toBe(true);
    }
  });

  it('matches suffix sensitive files', () => {
    const paths = [
      '/backup.sql',
      '/data_dump.sql.gz',
      '/app.tar.gz',
      '/config.php.bak',
      '/index.php.old',
      '/.bash_history.swp'
    ];

    for (const p of paths) {
      const norm = normalizePath(p);
      const res = matcher.match(norm);
      expect(res.matched, `Expected suffix match for ${p}`).toBe(true);
    }
  });

  it('detects directory traversal patterns', () => {
    const paths = [
      '/../../../../etc/passwd',
      '/..\\..\\win.ini',
      '/static/..%2f..%2fetc%2fshadow'
    ];

    for (const p of paths) {
      const norm = normalizePath(p);
      const res = matcher.match(norm);
      expect(res.matched, `Expected traversal match for ${p}`).toBe(true);
      expect(res.rule?.category).toBe('path-traversal');
    }
  });

  it('avoids false positives on legitimate application & content paths', () => {
    const legitimatePaths = [
      '/',
      '/about',
      '/contact-us',
      '/pricing',
      '/blog/wordpress-history',
      '/git/tutorial',
      '/tutorials/php-intro',
      '/.environment-guide',
      '/assets/env.js',
      '/static/css/admin.css',
      '/public/images/logo.png',
      '/docs/database-schema',
      '/.well-known/security.txt',
      '/robots.txt',
      '/favicon.ico',
      '/sitemap.xml'
    ];

    for (const p of legitimatePaths) {
      const norm = normalizePath(p);
      const res = matcher.match(norm);
      expect(res.matched, `Expected NO match for legitimate path: ${p}`).toBe(false);
    }
  });

  it('supports custom rule overrides and additions', () => {
    const customRuleset = compileRules([
      {
        id: 'custom-internal-backup',
        category: 'custom',
        severity: 'high',
        path: '/old-backup'
      }
    ]);
    const customMatcher = new MatcherEngine(customRuleset);

    const norm = normalizePath('/old-backup');
    const res = customMatcher.match(norm);
    expect(res.matched).toBe(true);
    expect(res.rule?.id).toBe('custom-internal-backup');
  });
});
