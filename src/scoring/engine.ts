import type { ScannerRecord, ScoringThresholds, SignalBreakdown } from '../types.js';
import type { Rule } from '../rules/types.js';
import type { NormalizationResult } from '../normalizer/index.js';

const SCANNER_UA_REGEX = /(masscan|zgrab|nmap|sqlmap|nikto|gobuster|dirbuster|nuclei|ffuf|httpx|acunetix|nessus|openvas|arachni|w3af)/i;

export interface ScoringInput {
  norm: NormalizationResult;
  rule?: Rule;
  scanner?: ScannerRecord;
  decoyFollowed?: boolean;
  userAgent?: string;
}

export interface ScoringResult {
  confidence: number;
  signals: string[];
  breakdown: SignalBreakdown[];
  isSuspicious: boolean;
  isScanner: boolean;
  isConfirmed: boolean;
}

export class ScoringEngine {
  private thresholds: ScoringThresholds;

  constructor(thresholds: Partial<ScoringThresholds> = {}) {
    this.thresholds = {
      suspicious: thresholds.suspicious ?? 40,
      scanner: thresholds.scanner ?? 70,
      confirmed: thresholds.confirmed ?? 90
    };
  }

  public getThresholds(): ScoringThresholds {
    return this.thresholds;
  }

  public calculateScore(input: ScoringInput): ScoringResult {
    const breakdown: SignalBreakdown[] = [];
    const signals: string[] = [];

    // 1. Decoy followed (Strongest signal)
    if (input.decoyFollowed) {
      signals.push('decoy-followed');
      breakdown.push({
        signal: 'decoy-followed',
        points: 60,
        reason: 'Client requested a canary path revealed exclusively in a previously served decoy'
      });
    }

    // 2. Rule match / Sensitive path
    if (input.rule) {
      const categorySignal = `${input.rule.category}-probe`;
      signals.push('known-sensitive-path', categorySignal);

      let rulePoints = 25;
      if (input.rule.severity === 'critical') {
        rulePoints = 45;
      } else if (input.rule.severity === 'high') {
        rulePoints = 35;
      } else if (input.rule.severity === 'medium') {
        rulePoints = 20;
      } else {
        rulePoints = 10;
      }

      breakdown.push({
        signal: 'known-sensitive-path',
        points: rulePoints,
        reason: `${input.norm.normalizedPath} matched rule ${input.rule.id} (${input.rule.category}, ${input.rule.severity})`
      });
    }

    // 3. Path traversal
    if (input.norm.traversalDetected) {
      signals.push('path-traversal');
      breakdown.push({
        signal: 'path-traversal',
        points: 35,
        reason: 'Path contains directory traversal sequences (e.g. ../ or encoded equivalents)'
      });
    }

    // 4. Encoding evasion / Null byte
    if (input.norm.hasNullByte) {
      signals.push('null-byte-injection');
      breakdown.push({
        signal: 'null-byte-injection',
        points: 30,
        reason: 'Request contains null byte %00 character'
      });
    } else if (input.norm.encodingDepth > 1) {
      signals.push('multi-encoded-path');
      breakdown.push({
        signal: 'multi-encoded-path',
        points: 20,
        reason: `Request path utilized ${input.norm.encodingDepth} layers of percent-encoding`
      });
    }

    // 5. User-Agent Scanner fingerprint & Evasion Detection
    if (input.userAgent && SCANNER_UA_REGEX.test(input.userAgent)) {
      signals.push('known-scanner-user-agent');
      breakdown.push({
        signal: 'known-scanner-user-agent',
        points: 15,
        reason: `User-Agent contains automated scanner signature (${input.userAgent.slice(0, 30)})`
      });
    }

    // Detect User-Agent swapping evasion
    if (input.scanner && input.userAgent && input.scanner.userAgents && input.scanner.userAgents.size > 0) {
      if (!input.scanner.userAgents.has(input.userAgent)) {
        signals.push('ua-swapping-evasion');
        breakdown.push({
          signal: 'ua-swapping-evasion',
          points: 25,
          reason: 'Client abruptly altered User-Agent within an active probe session to evade detection'
        });
      }
    }

    // 6. Session behavioral signals
    if (input.scanner) {
      const allCategories = new Set(input.scanner.categories);
      if (input.rule?.category) {
        allCategories.add(input.rule.category);
      }

      const allPaths = new Set(input.scanner.uniquePaths);
      allPaths.add(input.norm.normalizedPath);

      // Multiple probe categories
      if (allCategories.size >= 3) {
        signals.push('multiple-probe-categories');
        breakdown.push({
          signal: 'multiple-probe-categories',
          points: 25,
          reason: `Client probed ${allCategories.size} distinct probe categories`
        });
      } else if (allCategories.size === 2) {
        signals.push('multiple-probe-categories');
        breakdown.push({
          signal: 'multiple-probe-categories',
          points: 15,
          reason: 'Client probed 2 distinct probe categories'
        });
      }

      // Sustained sensitive file enumeration
      if (input.scanner.matchedRules.size >= 2) {
        signals.push('sustained-file-enumeration');
        breakdown.push({
          signal: 'sustained-file-enumeration',
          points: 15,
          reason: `Client has probed ${input.scanner.matchedRules.size} distinct sensitive targets`
        });
      }

      // Rapid path enumeration
      if (allPaths.size >= 10) {
        signals.push('rapid-path-enumeration');
        breakdown.push({
          signal: 'rapid-path-enumeration',
          points: 20,
          reason: `Client probed ${allPaths.size} unique paths`
        });
      } else if (allPaths.size >= 5) {
        signals.push('rapid-path-enumeration');
        breakdown.push({
          signal: 'rapid-path-enumeration',
          points: 10,
          reason: `Client probed ${allPaths.size} unique paths`
        });
      }
    }

    // Calculate total capped score
    let totalScore = breakdown.reduce((sum, item) => sum + item.points, 0);
    totalScore = Math.min(100, Math.max(0, totalScore));

    return {
      confidence: totalScore,
      signals: Array.from(new Set(signals)),
      breakdown,
      isSuspicious: totalScore >= this.thresholds.suspicious,
      isScanner: totalScore >= this.thresholds.scanner,
      isConfirmed: totalScore >= this.thresholds.confirmed
    };
  }
}
