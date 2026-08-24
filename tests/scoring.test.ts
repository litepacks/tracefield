import { describe, expect, it } from 'vitest';
import { createDetector } from '../src/detector.js';

describe('Confidence & Behavioral Scoring Engine', () => {
  it('assigns higher score to critical dotenv probes', async () => {
    const detector = createDetector();
    const result = await detector.inspect({
      path: '/.env',
      ip: '198.51.100.1'
    });

    expect(result.matched).toBe(true);
    expect(result.confidence).toBeGreaterThanOrEqual(45);
    expect(result.signals).toContain('known-sensitive-path');
    expect(result.signals).toContain('dotenv-probe');
  });

  it('elevates scanner score as client probes multiple distinct categories', async () => {
    const detector = createDetector({ tracking: { enabled: true } });
    const ip = '198.51.100.2';

    // 1st request: dotenv
    const res1 = await detector.inspect({ path: '/.env', ip });
    expect(res1.confidence).toBe(45);

    // 2nd request: git
    const res2 = await detector.inspect({ path: '/.git/config', ip });
    expect(res2.confidence).toBeGreaterThanOrEqual(60);
    expect(res2.signals).toContain('multiple-probe-categories');

    // 3rd request: backups
    const res3 = await detector.inspect({ path: '/site.zip', ip });
    expect(res3.confidence).toBeGreaterThanOrEqual(85);
  });

  it('detects automated scanner User-Agent as a weak signal but not sole blocker', async () => {
    const detector = createDetector();

    // Normal clean request with scanner UA
    const cleanResult = await detector.inspect({
      path: '/about-us',
      ip: '198.51.100.3',
      headers: { 'user-agent': 'sqlmap/1.6.12#stable (https://sqlmap.org)' }
    });

    // Score is low (15 points), not blocked on clean page
    expect(cleanResult.confidence).toBe(15);
    expect(cleanResult.matched).toBe(false);
    expect(cleanResult.blocked).toBe(false);

    // Sensitive probe with scanner UA
    const probeResult = await detector.inspect({
      path: '/.env',
      ip: '198.51.100.3',
      headers: { 'user-agent': 'sqlmap/1.6.12#stable (https://sqlmap.org)' }
    });

    expect(probeResult.confidence).toBe(60); // 45 + 15
    expect(probeResult.signals).toContain('known-scanner-user-agent');
  });

  it('generates a readable explanation via result.explain()', async () => {
    const detector = createDetector();
    const result = await detector.inspect({
      path: '/.env.production',
      ip: '198.51.100.4'
    });

    const explanation = result.explain();
    expect(explanation).toContain('Confidence: 45');
    expect(explanation).toContain('+45');
    expect(explanation).toContain('dotenv-exact-prod');
  });

  it('detects and penalizes User-Agent swapping evasion attempts within active session', async () => {
    const detector = createDetector({ tracking: { enabled: true } });
    const ip = '198.51.100.99';

    // 1st request with scanner UA
    const res1 = await detector.inspect({
      path: '/.env',
      ip,
      headers: { 'user-agent': 'python-requests/2.25.1' }
    });
    expect(res1.signals).toContain('known-sensitive-path');

    // 2nd request from same IP trying to masquerade as an iPhone Chrome browser
    const res2 = await detector.inspect({
      path: '/.git/config',
      ip,
      headers: { 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)' }
    });

    expect(res2.signals).toContain('ua-swapping-evasion');
    expect(res2.confidence).toBeGreaterThanOrEqual(85);
    expect(res2.session?.uaSwapped).toBe(true);
    expect(res2.explain()).toContain('Client abruptly altered User-Agent');
  });

  it('detects honeypot trap Bearer token reuse in request headers', async () => {
    const detector = createDetector();
    const result = await detector.inspect({
      path: '/api/v1/profile',
      headers: {
        authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZWNyZXRfZmluZ2VycHJpbnQiOiJ0cmFjZWZpZWxkX2p3dF9kXzk4ZjFhIn0.sig'
      }
    });

    expect(result.matched).toBe(true);
    expect(result.signals).toContain('decoy-followed');
    expect(result.confidence).toBeGreaterThanOrEqual(60);
  });
});
