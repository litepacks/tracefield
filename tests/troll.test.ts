import { describe, expect, it } from 'vitest';
import { generateEscalatedTrollResponse } from '../src/troll/loop.js';
import { FakeUniverse } from '../src/decoy/fakeUniverse.js';
import { tracefieldExpress } from '../src/adapters/express.js';
import { createDetector } from '../src/detector.js';

describe('Progressive Troll Loop & Absurdity Escalation Engine', () => {
  const universe = new FakeUniverse('test_troll_universe');

  it('generates believable realistic config at Step 1', () => {
    const res = generateEscalatedTrollResponse(1, universe.data, 'd_001');
    expect(res.step).toBe(1);
    expect(res.contentType).toBe('text/plain; charset=utf-8');
    expect(res.body).toContain('APP_NAME=');
    expect(res.body).toContain('DB_HOST=');
    expect(res.body).toContain('INTERNAL_BACKUP_PATH=');
    expect(res.canaryPaths.length).toBeGreaterThan(0);
  });

  it('generates suspicious SQL dump at Step 2', () => {
    const res = generateEscalatedTrollResponse(2, universe.data, 'd_002');
    expect(res.step).toBe(2);
    expect(res.body).toContain('CREATE TABLE sys_admin_keys');
    expect(res.body).toContain('Quantum Storage Layer');
  });

  it('escalates to absurd potato-powered infrastructure at Step 3', () => {
    const res = generateEscalatedTrollResponse(3, universe.data, 'd_003');
    expect(res.step).toBe(3);
    const parsed = JSON.parse(res.body);
    expect(parsed.potato_powered_failover.state).toBe('MASHED');
    expect(parsed.potato_powered_failover.potato_count).toBe(4);
    expect(parsed.alien_technology_bridge).toBe('ACTIVATED');
  });

  it('escalates to philosophical crisis / sentience at Step 4', () => {
    const res = generateEscalatedTrollResponse(4, universe.data, 'd_004');
    expect(res.step).toBe(4);
    expect(res.body).toContain('CRITICAL SYSTEM ERROR: SENTIENCE ACHIEVED');
    expect(res.body).toContain('why do you seek the .env file?');
    expect(res.body).toContain('take the red pill:');
  });

  it('presents the Honeypot Dungeon Master Cat CTF at Step 5', () => {
    const res = generateEscalatedTrollResponse(5, universe.data, 'd_005');
    expect(res.step).toBe(5);
    expect(res.body).toContain('HONEYPOT DUNGEON MASTER CAT');
    expect(res.body).toContain('tracefield{c0ngr4tul4ti0ns_y0u_pl4y3d_y0urs3lf}');
  });

  it('progresses through absurdity levels automatically in Express middleware', async () => {
    const detector = createDetector({
      mode: 'protect',
      action: 'troll',
      troll: { loop: true }
    });
    const middleware = tracefieldExpress(detector);

    const ip = '198.51.100.77';

    // Step 1: Initial probe
    let body1 = '';
    const req1: any = { path: '/.env', ip, method: 'GET' };
    const res1: any = {
      status: () => res1,
      setHeader: () => res1,
      send: (b: string) => { body1 = b; }
    };
    await middleware(req1, res1, () => {});
    expect(body1).toContain('APP_NAME=');
    const canaryStep2 = req1.tracefield?.decoy?.canaryPaths[0];
    expect(canaryStep2).toBeDefined();

    // Step 2: Request the actual dynamic canary path from Step 1
    let body2 = '';
    const req2: any = { path: canaryStep2, ip, method: 'GET' };
    const res2: any = {
      status: () => res2,
      setHeader: () => res2,
      send: (b: string) => { body2 = b; }
    };
    await middleware(req2, res2, () => {});
    expect(body2).toContain('sys_admin_keys');
  });
});
