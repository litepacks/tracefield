import type { Rule, RuleCategory, SeverityLevel } from './rules/types.js';

export type ActionType = 'allow' | 'block' | 'silent' | 'decoy' | 'troll' | 'observe';
export type TrollType =
  | 'teapot'
  | 'nice-try'
  | 'fake-error'
  | 'empty-200'
  | 'php-leak'
  | 'php-error'
  | 'ftp-leak'
  | 'rsa-troll'
  | 'fake-graphql'
  | 'fake-jwt'
  | 'tarpit'
  | 'loop'
  | 'rickroll';
export type Mode = 'observe' | 'protect';

export interface HttpRequest {
  path: string;
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
  ip?: string;
  rawUrl?: string;
}

export interface SignalBreakdown {
  signal: string;
  points: number;
  reason: string;
}

export interface DecoyPayload {
  decoyId: string;
  status: number;
  contentType: string;
  body: string;
  headers?: Record<string, string>;
  canaryPaths: string[];
}

export interface ScannerSessionInfo {
  scannerId: string;
  sessionId: string;
  requests: number;
  uniquePaths: number;
  startedAt: number;
  lastSeenAt: number;
  categories: string[];
  confidence: number;
  followedDecoys?: number;
  uaSwapped?: boolean;
  loopStep?: number;
}

export interface InspectionResult {
  matched: boolean;
  blocked: boolean;
  action: ActionType;
  category?: RuleCategory;
  rule?: string;
  severity?: SeverityLevel;
  confidence: number;
  signals: string[];
  scoreBreakdown: SignalBreakdown[];
  session?: ScannerSessionInfo;
  decoy?: DecoyPayload;
  rawPath: string;
  normalizedPath: string;
  explain: () => string;
}

export interface ScoringThresholds {
  suspicious: number; // default: 40
  scanner: number;    // default: 70
  confirmed: number;  // default: 90
}

export interface TrackingOptions {
  enabled?: boolean;
  ttl?: string | number; // e.g. '15m' or 900000 ms
  maxSessions?: number;  // default: 5000
  maskIp?: boolean;      // default: true
  hashIdentifiers?: boolean;
}

export interface DecoyOptions {
  enabled?: boolean;
  perScanner?: boolean;  // default: true (deterministic per scanner)
  maxDepth?: number;     // default: 3
  seed?: string;
  brandName?: string;
  overrideDecoys?: Record<string, (context: DecoyContext) => DecoyPayload>;
}

export interface DecoyContext {
  scannerId: string;
  sessionId: string;
  path: string;
  rule?: Rule;
  universe: any;
  depth: number;
  parentDecoyId?: string;
}

export interface TrollOptions {
  type?: TrollType;     // default: 'nice-try'
  customBody?: string;
  loop?: boolean;       // Progressive absurdity escalation loop
  maxSteps?: number;    // default: 10
}

export interface DetectorOptions {
  mode?: Mode;
  action?: ActionType;
  responseStatus?: number; // 403 or 404 (default: 404)
  actions?: Partial<Record<RuleCategory, ActionType>>;
  scoring?: Partial<ScoringThresholds>;
  tracking?: TrackingOptions;
  decoy?: DecoyOptions;
  troll?: TrollOptions;
  rules?: (Rule | import('./rules/types.js').RawRule)[];
  exclusions?: (string | RegExp)[];
  storage?: StorageAdapter;
}

export interface DecoyRecord {
  decoyId: string;
  scannerId: string;
  sourcePath: string;
  canaryPaths: string[];
  parentDecoyId?: string;
  createdAt: number;
  depth: number;
}

export interface ScannerRecord {
  scannerId: string;
  sessionId: string;
  ipMasked: string;
  userAgent?: string;
  userAgents: Set<string>;
  requests: number;
  uniquePaths: Set<string>;
  categories: Set<string>;
  matchedRules: Set<string>;
  signals: Set<string>;
  activeDecoys: Map<string, DecoyRecord>;
  followedDecoys: number;
  firstSeen: number;
  lastSeen: number;
  confidence: number;
}

export interface StorageAdapter {
  getScanner(scannerId: string): Promise<ScannerRecord | undefined> | ScannerRecord | undefined;
  saveScanner(scanner: ScannerRecord): Promise<void> | void;
  saveDecoy(decoy: DecoyRecord): Promise<void> | void;
  getDecoy(decoyId: string): Promise<DecoyRecord | undefined> | DecoyRecord | undefined;
  getDecoyByCanary(canaryPath: string): Promise<DecoyRecord | undefined> | DecoyRecord | undefined;
  cleanup?(): Promise<void> | void;
}
