import { describe, expect, it } from 'vitest';
import { createDetector } from '../src/detector.js';
import { FakeUniverse } from '../src/decoy/fakeUniverse.js';
import { DecoyEngine } from '../src/decoy/engine.js';

describe('Decoy Engine & Fake Universe', () => {
  it('generates deterministic fake infrastructure for the same scanner', () => {
    const universe1 = new FakeUniverse('scanner_session_alpha');
    const universe2 = new FakeUniverse('scanner_session_alpha');

    expect(universe1.data.appName).toBe(universe2.data.appName);
    expect(universe1.data.dbHost).toBe(universe2.data.dbHost);
    expect(universe1.data.dbUser).toBe(universe2.data.dbUser);
    expect(universe1.data.secretSuffix).toBe(universe2.data.secretSuffix);
  });

  it('generates distinct fake environments for different scanners', () => {
    const universeA = new FakeUniverse('scanner_alpha_123');
    const universeB = new FakeUniverse('scanner_beta_456');

    // At least one or more fields differ
    const areDifferent =
      universeA.data.dbHost !== universeB.data.dbHost ||
      universeA.data.secretSuffix !== universeB.data.secretSuffix ||
      universeA.data.appName !== universeB.data.appName;

    expect(areDifferent).toBe(true);
  });

  it('enforces safety constraints on fake generated credentials and IPs', () => {
    const universe = new FakeUniverse('security_check_scanner');
    const token = universe.getSecretToken();

    // Must have recognizable fake prefix
    expect(token).toMatch(/^tracefield_fake_[0-9a-f]{6}$/);

    // DB IP must be in private RFC 1918 10.x.x.x range
    expect(universe.data.dbHost).toMatch(/^10\.24\.\d+\.\d+$/);
  });

  it('serves fake .env with canary tokens when requested', async () => {
    const detector = createDetector({
      mode: 'protect',
      action: 'decoy',
      decoy: { enabled: true }
    });

    const result = await detector.inspect({
      path: '/.env',
      ip: '198.51.100.10'
    });

    expect(result.matched).toBe(true);
    expect(result.action).toBe('decoy');
    expect(result.decoy).toBeDefined();
    expect(result.decoy?.contentType).toContain('text/plain');
    expect(result.decoy?.body).toContain('APP_NAME=');
    expect(result.decoy?.body).toContain('INTERNAL_API_KEY=tracefield_decoy_');
    expect(result.decoy?.canaryPaths.length).toBeGreaterThan(0);
  });

  it('generates deterministic realistic .env decoy with canary path', async () => {
    const engine = new DecoyEngine();
    const result = await engine.generateDecoy('/.env', 'scanner_123');

    expect(result.status).toBe(200);
    expect(result.contentType).toBe('text/plain; charset=utf-8');
    expect(result.body).toContain('APP_NAME=');
    expect(result.body).toContain('DB_HOST=');
    expect(result.body).toContain('DB_PASSWORD=tracefield_fake_db_');
    expect(result.body).toContain('INTERNAL_API_KEY=tracefield_decoy_');
    expect(result.canaryPaths.length).toBeGreaterThan(0);
  });

  it('generates consistent decoys for the same scanner across multiple requests', async () => {
    const engine = new DecoyEngine();
    const result1 = await engine.generateDecoy('/.env', 'scanner_abc');
    const result2 = await engine.generateDecoy('/.env', 'scanner_abc');

    // Universe credentials should be deterministic for the same scanner
    const universe1 = engine.getUniverseForScanner('scanner_abc');
    const universe2 = engine.getUniverseForScanner('scanner_abc');
    expect(universe1.data.appName).toBe(universe2.data.appName);
    expect(universe1.data.dbHost).toBe(universe2.data.dbHost);
    expect(result1.body).toContain(`APP_NAME=${universe1.data.appName}`);
    expect(result2.body).toContain(`APP_NAME=${universe2.data.appName}`);
  });

  it('generates SFTP config decoy with canary backup endpoint', async () => {
    const engine = new DecoyEngine();
    const result = await engine.generateDecoy('/sftp-config.json', 'scanner_sftp');

    expect(result.status).toBe(200);
    expect(result.contentType).toBe('application/json; charset=utf-8');
    expect(result.body).toContain('"type": "sftp"');
    expect(result.body).toContain('"password": "tracefield_fake_ftp_');
    expect(result.body).toContain('backup_canary_endpoint');
    expect(result.canaryPaths.length).toBe(1);
    expect(result.canaryPaths[0]).toContain('/internal/ftp-storage/');
  });

  it('generates RSA private key decoy with embedded ASCII troll face', async () => {
    const engine = new DecoyEngine();
    const result = await engine.generateDecoy('/.ssh/id_rsa', 'scanner_ssh');

    expect(result.status).toBe(200);
    expect(result.contentType).toBe('text/plain; charset=utf-8');
    expect(result.body).toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(result.body).toContain('░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░');
    expect(result.body).toContain('Key-Fingerprint: SHA256:tracefield_fake_rsa_');
    expect(result.body).toContain('Flag: tracefield{pr1v4t3_k3y_tr0ll_f4c3_h0n3yp0t}');
    expect(result.body).toContain('-----END RSA PRIVATE KEY-----');
    expect(result.canaryPaths.length).toBe(1);
    expect(result.canaryPaths[0]).toContain('/internal/ssh-keys/');
  });

  it('tracks decoy interaction and increases confidence when scanner follows canary path', async () => {
    const detector = createDetector({
      mode: 'protect',
      action: 'decoy',
      decoy: { enabled: true, maxDepth: 3 }
    });

    let followedEventFired = false;
    detector.on('decoy.followed', () => {
      followedEventFired = true;
    });

    const ip = '198.51.100.20';

    // 1. Initial probe on /.env
    const firstResult = await detector.inspect({ path: '/.env', ip });
    expect(firstResult.decoy).toBeDefined();
    const canaryPath = firstResult.decoy!.canaryPaths[0];
    expect(canaryPath).toBeDefined();

    // 2. Scanner parses .env and requests the canary path
    const followedResult = await detector.inspect({ path: canaryPath, ip });

    expect(followedEventFired).toBe(true);
    expect(followedResult.matched).toBe(true);
    expect(followedResult.signals).toContain('decoy-followed');
    expect(followedResult.confidence).toBeGreaterThanOrEqual(90);
    expect(followedResult.decoy).toBeDefined();
    expect(followedResult.explain()).toContain('Client requested a canary path revealed exclusively');
  });

  it('respects maxDepth to prevent endless decoy loops', async () => {
    const detector = createDetector({
      mode: 'protect',
      action: 'decoy',
      decoy: { enabled: true, maxDepth: 2 }
    });

    const ip = '198.51.100.30';

    // Depth 1: /.env
    const res1 = await detector.inspect({ path: '/.env', ip });
    const canary1 = res1.decoy!.canaryPaths[0];

    // Depth 2: canary1
    const res2 = await detector.inspect({ path: canary1, ip });
    expect(res2.decoy).toBeDefined();
    const canary2 = res2.decoy!.canaryPaths[0];

    // Depth 3: exceeding maxDepth 2
    const res3 = await detector.inspect({ path: canary2, ip });
    expect(res3.decoy).toBeUndefined(); // stops generating further decoys
  });
});
