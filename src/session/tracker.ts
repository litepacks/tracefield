import type { HttpRequest, ScannerRecord, StorageAdapter, TrackingOptions } from '../types.js';
import { MemoryStore } from './memoryStore.js';

export function parseTtl(ttl: string | number | undefined): number {
  if (typeof ttl === 'number') return ttl;
  if (!ttl) return 15 * 60 * 1000; // 15m default

  const match = /^(\d+)\s*([smhd])?$/i.exec(ttl.trim());
  if (!match) return 15 * 60 * 1000;

  const val = parseInt(match[1], 10);
  const unit = (match[2] || 'm').toLowerCase();

  switch (unit) {
    case 's': return val * 1000;
    case 'm': return val * 60 * 1000;
    case 'h': return val * 60 * 60 * 1000;
    case 'd': return val * 24 * 60 * 60 * 1000;
    default: return val * 60 * 1000;
  }
}

export function maskIp(ip: string | undefined): string {
  if (!ip || ip === 'unknown') return 'anonymous';

  // IPv4 masking
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
  }

  // IPv6 masking
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    if (parts.length >= 3) {
      return `${parts[0]}:${parts[1]}:${parts[2]}::/48`;
    }
  }

  return 'masked_ip';
}

function simpleHash(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16);
}

export class ScannerTracker {
  private storage: StorageAdapter;
  private options: TrackingOptions;

  constructor(options: TrackingOptions = {}, customStorage?: StorageAdapter) {
    this.options = {
      enabled: options.enabled ?? true,
      ttl: options.ttl ?? '15m',
      maxSessions: options.maxSessions ?? 5000,
      maskIp: options.maskIp ?? true,
      hashIdentifiers: options.hashIdentifiers ?? false
    };

    this.storage = customStorage || new MemoryStore({
      ttlMs: parseTtl(this.options.ttl),
      maxSessions: this.options.maxSessions
    });
  }

  public getStorage(): StorageAdapter {
    return this.storage;
  }

  public generateIdentifiers(req: HttpRequest): { scannerId: string; sessionId: string; ipMasked: string } {
    const rawIp = req.ip || (typeof req.headers?.['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'].split(',')[0].trim() : '127.0.0.1');
    const userAgent = typeof req.headers?.['user-agent'] === 'string' ? req.headers['user-agent'] : '';

    const ipMasked = this.options.maskIp ? maskIp(rawIp) : rawIp;

    const hash = simpleHash(ipMasked);
    const scannerId = `sc_${hash}`;
    const sessionId = `sess_${hash}_${Math.floor(Date.now() / (15 * 60 * 1000))}`;

    return { scannerId, sessionId, ipMasked };
  }

  public async getOrCreateScanner(req: HttpRequest): Promise<ScannerRecord> {
    const { scannerId, sessionId, ipMasked } = this.generateIdentifiers(req);
    const userAgent = typeof req.headers?.['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;

    let record = await this.storage.getScanner(scannerId);

    if (!record) {
      record = {
        scannerId,
        sessionId,
        ipMasked,
        userAgent,
        userAgents: new Set(userAgent ? [userAgent] : []),
        requests: 0,
        uniquePaths: new Set<string>(),
        categories: new Set<string>(),
        matchedRules: new Set<string>(),
        signals: new Set<string>(),
        activeDecoys: new Map(),
        followedDecoys: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        confidence: 0
      };
    }

    return record;
  }

  public async recordRequest(
    record: ScannerRecord,
    path: string,
    category?: string,
    ruleId?: string,
    signals: string[] = [],
    userAgent?: string
  ): Promise<void> {
    record.requests++;
    record.lastSeen = Date.now();
    record.uniquePaths.add(path);

    if (userAgent) {
      record.userAgents.add(userAgent);
      record.userAgent = userAgent;
    }

    if (category) {
      record.categories.add(category);
    }
    if (ruleId) {
      record.matchedRules.add(ruleId);
    }
    for (const sig of signals) {
      record.signals.add(sig);
    }

    await this.storage.saveScanner(record);
  }
}
