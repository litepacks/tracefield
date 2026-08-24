import { describe, expect, it } from 'vitest';
import { normalizePath } from '../src/normalizer/index.js';

describe('Path Normalizer', () => {
  it('normalizes standard clean paths', () => {
    const result = normalizePath('/users/profile');
    expect(result.rawPath).toBe('/users/profile');
    expect(result.normalizedPath).toBe('/users/profile');
    expect(result.traversalDetected).toBe(false);
    expect(result.encodingDepth).toBe(0);
  });

  it('handles duplicate slashes', () => {
    const result = normalizePath('//.env');
    expect(result.rawPath).toBe('//.env');
    expect(result.normalizedPath).toBe('/.env');
  });

  it('handles single URL encoding (%2eenv -> /.env)', () => {
    const result = normalizePath('/%2eenv');
    expect(result.normalizedPath).toBe('/.env');
    expect(result.encodingDepth).toBeGreaterThanOrEqual(1);
  });

  it('handles uppercase URL encoding (%2Eenv -> /.env)', () => {
    const result = normalizePath('/%2Eenv');
    expect(result.normalizedPath).toBe('/.env');
  });

  it('handles mixed partial encoding (/.%65nv -> /.env)', () => {
    const result = normalizePath('/.%65nv');
    expect(result.normalizedPath).toBe('/.env');
  });

  it('handles double URL encoding (%252e%252e/ -> /../)', () => {
    const result = normalizePath('/%252e%252e/etc/passwd');
    expect(result.traversalDetected).toBe(true);
    expect(result.encodingDepth).toBeGreaterThanOrEqual(2);
    expect(result.suspiciousChars).toBe(true);
  });

  it('handles backslashes', () => {
    const result = normalizePath('\\wp-admin\\login.php');
    expect(result.normalizedPath).toBe('/wp-admin/login.php');
  });

  it('resolves dot segments and flags traversal', () => {
    const result = normalizePath('/static/../.env');
    expect(result.normalizedPath).toBe('/.env');
    expect(result.traversalDetected).toBe(true);
  });

  it('strips query strings and hashes while preserving rawPath', () => {
    const result = normalizePath('/.env.production?version=1#secret');
    expect(result.rawPath).toBe('/.env.production?version=1#secret');
    expect(result.normalizedPath).toBe('/.env.production');
  });

  it('detects and strips null bytes', () => {
    const result = normalizePath('/backup.sql%00.jpg');
    expect(result.hasNullByte).toBe(true);
    expect(result.normalizedPath).toBe('/backup.sql.jpg');
  });
});
