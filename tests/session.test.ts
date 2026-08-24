import { describe, expect, it } from 'vitest';
import { maskIp, parseTtl, ScannerTracker } from '../src/session/tracker.js';
import { MemoryStore } from '../src/session/memoryStore.js';

describe('Scanner Session & Privacy Tracking', () => {
  it('correctly parses human-readable TTL strings', () => {
    expect(parseTtl('30s')).toBe(30 * 1000);
    expect(parseTtl('15m')).toBe(15 * 60 * 1000);
    expect(parseTtl('2h')).toBe(2 * 60 * 60 * 1000);
    expect(parseTtl('1d')).toBe(24 * 60 * 60 * 1000);
    expect(parseTtl(5000)).toBe(5000);
  });

  it('masks IPv4 addresses for privacy', () => {
    expect(maskIp('192.168.1.45')).toBe('192.168.1.0/24');
    expect(maskIp('10.0.5.123')).toBe('10.0.5.0/24');
  });

  it('masks IPv6 addresses for privacy', () => {
    const masked = maskIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    expect(masked).toBe('2001:0db8:85a3::/48');
  });

  it('evicts expired sessions in MemoryStore', () => {
    const store = new MemoryStore({ ttlMs: 50 }); // 50ms TTL

    store.saveScanner({
      scannerId: 'sc_test_1',
      sessionId: 'sess_1',
      ipMasked: '1.2.3.0/24',
      requests: 1,
      uniquePaths: new Set(['/.env']),
      categories: new Set(['dotenv']),
      matchedRules: new Set(['dotenv-root']),
      signals: new Set(),
      activeDecoys: new Map(),
      followedDecoys: 0,
      firstSeen: Date.now() - 100,
      lastSeen: Date.now() - 100, // already expired
      confidence: 50
    });

    expect(store.getScanner('sc_test_1')).toBeUndefined();
  });
});
