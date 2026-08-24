import type { DecoyPayload, DecoyRecord, HttpRequest, InspectionResult, ScannerRecord } from '../types.js';
import type { Rule } from '../rules/types.js';

export interface TracefieldEventMap {
  'request.inspected': { request: HttpRequest; result: InspectionResult };
  'rule.matched': { rule: Rule; request: HttpRequest; result: InspectionResult };
  'request.blocked': { request: HttpRequest; result: InspectionResult };
  'decoy.served': { decoy: DecoyPayload; request: HttpRequest; scannerId: string };
  'decoy.followed': { decoy: DecoyRecord; request: HttpRequest; scannerId: string };
  'scanner.created': { scanner: ScannerRecord };
  'scanner.updated': { scanner: ScannerRecord };
  'scanner.confirmed': { scanner: ScannerRecord };
  'score.changed': { scannerId: string; oldScore: number; newScore: number };
}

export type TracefieldEventListener<K extends keyof TracefieldEventMap> = (event: TracefieldEventMap[K]) => void;

export class TypedEventEmitter {
  private listeners = new Map<keyof TracefieldEventMap, Set<TracefieldEventListener<any>>>();

  public on<K extends keyof TracefieldEventMap>(event: K, listener: TracefieldEventListener<K>): () => void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);

    return () => {
      this.off(event, listener);
    };
  }

  public off<K extends keyof TracefieldEventMap>(event: K, listener: TracefieldEventListener<K>): void {
    const set = this.listeners.get(event);
    if (set) {
      set.delete(listener);
    }
  }

  public emit<K extends keyof TracefieldEventMap>(event: K, data: TracefieldEventMap[K]): void {
    const set = this.listeners.get(event);
    if (!set) return;

    for (const listener of set) {
      try {
        listener(data);
      } catch (err) {
        if (process.env.NODE_ENV !== 'test') {
          console.error(`[tracefield] Error in '${event}' event listener:`, err);
        }
      }
    }
  }
}
