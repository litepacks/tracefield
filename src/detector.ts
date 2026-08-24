import type {
  ActionType,
  DecoyPayload,
  DecoyRecord,
  DetectorOptions,
  HttpRequest,
  InspectionResult,
  ScannerRecord,
  ScannerSessionInfo
} from './types.js';
import { compileRules } from './rules/compiler.js';
import { normalizePath } from './normalizer/index.js';
import { MatcherEngine } from './matcher/index.js';
import { ScannerTracker } from './session/tracker.js';
import { DecoyEngine } from './decoy/engine.js';
import { ScoringEngine } from './scoring/engine.js';
import { TypedEventEmitter } from './events/emitter.js';
import { formatExplain } from './explain/index.js';
import { resolveActionResponse, type ActionResponse } from './actions/index.js';
import { generateEscalatedTrollResponse } from './troll/loop.js';

export class Detector extends TypedEventEmitter {
  private options: DetectorOptions;
  private matcher: MatcherEngine;
  private tracker: ScannerTracker;
  private decoyEngine: DecoyEngine;
  private scorer: ScoringEngine;

  constructor(options: DetectorOptions = {}) {
    super();
    this.options = {
      mode: options.mode || 'observe',
      action: options.action || 'block',
      responseStatus: options.responseStatus || 404,
      ...options
    };

    const compiledRules = compileRules(options.rules, options.exclusions);
    this.matcher = new MatcherEngine(compiledRules);
    this.tracker = new ScannerTracker(options.tracking, options.storage);
    this.decoyEngine = new DecoyEngine(options.decoy, this.tracker.getStorage());
    this.scorer = new ScoringEngine(options.scoring);
  }

  public getOptions(): DetectorOptions {
    return this.options;
  }

  public async inspect(req: HttpRequest): Promise<InspectionResult> {
    const norm = normalizePath(req.path);
    const userAgent = typeof req.headers?.['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;

    // 1. Check if the path or headers contain a followed canary token
    let decoyFollowed = false;
    let parentDecoy: DecoyRecord | undefined;

    const storage = this.tracker.getStorage();
    const existingDecoy = await storage.getDecoyByCanary(norm.normalizedPath);
    if (existingDecoy) {
      decoyFollowed = true;
      parentDecoy = existingDecoy;
    }

    // Check header / token canaries (e.g. Bearer JWT trap token or Cookie honeypot)
    let authHeader = '';
    let cookieHeader = '';
    if (req.headers) {
      for (const [k, v] of Object.entries(req.headers)) {
        const lowerKey = k.toLowerCase();
        if (lowerKey === 'authorization' && typeof v === 'string') {
          authHeader = v;
        } else if (lowerKey === 'cookie' && typeof v === 'string') {
          cookieHeader = v;
        }
      }
    }

    if (authHeader.includes('tracefield_') || cookieHeader.includes('tracefield_')) {
      decoyFollowed = true;
    } else if (authHeader.toLowerCase().startsWith('bearer ')) {
      try {
        const tokenParts = authHeader.slice(7).trim().split('.');
        if (tokenParts.length >= 2) {
          const decodedPayload = Buffer.from(tokenParts[1], 'base64').toString('utf-8');
          if (decodedPayload.includes('tracefield_')) {
            decoyFollowed = true;
          }
        }
      } catch {
        // ignore malformed base64
      }
    }

    // 2. Match rules
    const matchResult = this.matcher.match(norm);
    const rule = matchResult.rule;

    // 3. Resolve scanner session
    let scanner: ScannerRecord | undefined;
    if (this.options.tracking?.enabled !== false) {
      scanner = await this.tracker.getOrCreateScanner(req);
    }

    // 4. Calculate confidence & behavioral score
    const scoreResult = this.scorer.calculateScore({
      norm,
      rule,
      scanner,
      decoyFollowed,
      userAgent
    });

    const isMatch = matchResult.matched || decoyFollowed || scoreResult.isSuspicious;

    // 5. Generate Decoy or Troll Loop payload if enabled
    let decoyPayload: DecoyPayload | undefined;
    const isDecoyCandidate = (rule && ['dotenv', 'secrets', 'wordpress', 'database', 'git', 'php'].includes(rule.category)) || decoyFollowed;

    if (this.options.troll?.loop || this.options.troll?.type === 'loop') {
      const step = parentDecoy ? parentDecoy.depth + 1 : 1;
      const universe = this.decoyEngine.getUniverseForScanner(scanner?.scannerId || 'anonymous_scanner');
      const decoyId = `d_${Date.now().toString(36).slice(-4)}${Math.random().toString(16).substring(2, 6)}`;
      const loopRes = generateEscalatedTrollResponse(step, universe.data, decoyId);

      decoyPayload = {
        decoyId,
        status: loopRes.status,
        contentType: loopRes.contentType,
        body: loopRes.body,
        canaryPaths: loopRes.canaryPaths
      };

      await storage.saveDecoy({
        decoyId,
        scannerId: scanner?.scannerId || 'anonymous_scanner',
        sourcePath: norm.normalizedPath,
        canaryPaths: loopRes.canaryPaths,
        parentDecoyId: parentDecoy?.decoyId,
        createdAt: Date.now(),
        depth: step
      });
    } else if (isDecoyCandidate && (this.options.action === 'decoy' || (rule && this.options.actions?.[rule.category] === 'decoy') || this.options.decoy?.enabled)) {
      decoyPayload = await this.decoyEngine.generateDecoy(
        norm.normalizedPath,
        scanner?.scannerId || 'anonymous_scanner',
        rule,
        parentDecoy
      );
    }

    // 6. Determine Action
    let targetAction: ActionType = 'allow';

    if (isMatch) {
      if (this.options.troll?.loop || this.options.troll?.type === 'loop' || this.options.action === 'troll') {
        targetAction = 'troll';
      } else if (rule && this.options.actions?.[rule.category]) {
        targetAction = this.options.actions[rule.category]!;
      } else if (decoyPayload && this.options.action === 'decoy') {
        targetAction = 'decoy';
      } else {
        targetAction = this.options.action || 'block';
      }
    }

    const isBlocked = this.options.mode === 'protect' && targetAction !== 'allow' && targetAction !== 'observe';

    // 7. Update session tracker
    if (scanner && this.options.tracking?.enabled !== false) {
      const oldConfidence = scanner.confidence;
      scanner.confidence = scoreResult.confidence;

      if (decoyFollowed) {
        scanner.followedDecoys++;
      }

      await this.tracker.recordRequest(
        scanner,
        norm.normalizedPath,
        rule?.category,
        rule?.id,
        scoreResult.signals,
        userAgent
      );

      if (scanner.requests === 1) {
        this.emit('scanner.created', { scanner });
      } else {
        this.emit('scanner.updated', { scanner });
      }

      if (scoreResult.isConfirmed && oldConfidence < this.scorer.getThresholds().confirmed) {
        this.emit('scanner.confirmed', { scanner });
      }

      if (oldConfidence !== scoreResult.confidence) {
        this.emit('score.changed', {
          scannerId: scanner.scannerId,
          oldScore: oldConfidence,
          newScore: scoreResult.confidence
        });
      }
    }

    // Session info presentation
    const sessionInfo: ScannerSessionInfo | undefined = scanner
      ? {
          scannerId: scanner.scannerId,
          sessionId: scanner.sessionId,
          requests: scanner.requests,
          uniquePaths: scanner.uniquePaths.size,
          startedAt: scanner.firstSeen,
          lastSeenAt: scanner.lastSeen,
          categories: Array.from(scanner.categories),
          confidence: scanner.confidence,
          followedDecoys: scanner.followedDecoys,
          uaSwapped: scoreResult.signals.includes('ua-swapping-evasion')
        }
      : undefined;

    const result: InspectionResult = {
      matched: isMatch,
      blocked: isBlocked,
      action: targetAction,
      category: rule?.category,
      rule: rule?.id,
      severity: rule?.severity,
      confidence: scoreResult.confidence,
      signals: scoreResult.signals,
      scoreBreakdown: scoreResult.breakdown,
      session: sessionInfo,
      decoy: decoyPayload,
      rawPath: norm.rawPath,
      normalizedPath: norm.normalizedPath,
      explain: () => formatExplain(scoreResult.confidence, scoreResult.breakdown, norm.rawPath, rule?.id)
    };

    // 8. Emit structured events
    this.emit('request.inspected', { request: req, result });

    if (rule) {
      this.emit('rule.matched', { rule, request: req, result });
    }

    if (isBlocked) {
      this.emit('request.blocked', { request: req, result });
    }

    if (decoyFollowed && existingDecoy) {
      this.emit('decoy.followed', {
        decoy: existingDecoy,
        request: req,
        scannerId: scanner?.scannerId || 'anonymous'
      });
    }

    if (decoyPayload) {
      this.emit('decoy.served', {
        decoy: decoyPayload,
        request: req,
        scannerId: scanner?.scannerId || 'anonymous'
      });
    }

    return result;
  }

  public resolveResponse(result: InspectionResult): ActionResponse {
    const scannerId = result.session?.scannerId || 'anonymous_scanner';
    const universe = this.decoyEngine.getUniverseForScanner(scannerId);
    const step = (result.session?.followedDecoys || 0) + 1;

    return resolveActionResponse(
      result.action,
      this.options.mode || 'observe',
      this.options.responseStatus || 404,
      result.decoy,
      this.options.troll,
      {
        loopStep: step,
        universeData: universe.data,
        decoyId: result.decoy?.decoyId || `d_${step}`
      }
    );
  }
}

/**
 * Factory helper to create a new Detector instance
 */
export function createDetector(options?: DetectorOptions): Detector {
  return new Detector(options);
}

/**
 * Standalone direct inspect function
 */
export async function inspect(
  request: HttpRequest,
  options?: DetectorOptions
): Promise<InspectionResult> {
  const detector = new Detector(options);
  return detector.inspect(request);
}
