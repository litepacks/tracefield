import type { DecoyRecord, ScannerRecord, StorageAdapter } from '../types.js';

export interface MemoryStoreOptions {
  ttlMs?: number;
  maxSessions?: number;
}

export class MemoryStore implements StorageAdapter {
  private scanners = new Map<string, ScannerRecord>();
  private decoys = new Map<string, DecoyRecord>();
  private canaryIndex = new Map<string, string>(); // canaryPath -> decoyId
  private ttlMs: number;
  private maxSessions: number;

  constructor(options: MemoryStoreOptions = {}) {
    this.ttlMs = options.ttlMs ?? 15 * 60 * 1000; // 15 minutes default
    this.maxSessions = options.maxSessions ?? 5000;
  }

  public getScanner(scannerId: string): ScannerRecord | undefined {
    const record = this.scanners.get(scannerId);
    if (!record) return undefined;

    if (Date.now() - record.lastSeen > this.ttlMs) {
      this.scanners.delete(scannerId);
      return undefined;
    }

    return record;
  }

  public saveScanner(scanner: ScannerRecord): void {
    if (this.scanners.size >= this.maxSessions && !this.scanners.has(scanner.scannerId)) {
      this.evictOldest();
    }
    this.scanners.set(scanner.scannerId, scanner);
  }

  public saveDecoy(decoy: DecoyRecord): void {
    this.decoys.set(decoy.decoyId, decoy);
    for (const canary of decoy.canaryPaths) {
      this.canaryIndex.set(canary.toLowerCase(), decoy.decoyId);
    }
  }

  public getDecoy(decoyId: string): DecoyRecord | undefined {
    return this.decoys.get(decoyId);
  }

  public getDecoyByCanary(canaryPath: string): DecoyRecord | undefined {
    const decoyId = this.canaryIndex.get(canaryPath.toLowerCase());
    if (!decoyId) return undefined;
    return this.decoys.get(decoyId);
  }

  public cleanup(): void {
    const now = Date.now();
    for (const [id, record] of this.scanners.entries()) {
      if (now - record.lastSeen > this.ttlMs) {
        this.scanners.delete(id);
      }
    }
    for (const [id, decoy] of this.decoys.entries()) {
      if (now - decoy.createdAt > this.ttlMs * 2) {
        this.decoys.delete(id);
        for (const canary of decoy.canaryPaths) {
          this.canaryIndex.delete(canary.toLowerCase());
        }
      }
    }
  }

  private evictOldest(): void {
    let oldestKey: string | undefined;
    let oldestTime = Infinity;

    for (const [key, value] of this.scanners.entries()) {
      if (value.lastSeen < oldestTime) {
        oldestTime = value.lastSeen;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.scanners.delete(oldestKey);
    }
  }
}
