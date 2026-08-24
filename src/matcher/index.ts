import type { CompiledRuleSet, Rule } from '../rules/types.js';
import type { NormalizationResult } from '../normalizer/index.js';
import { matchPrefixTrie } from './trie.js';

export interface MatchResult {
  matched: boolean;
  rule?: Rule;
  matchType?: 'exact' | 'prefix' | 'suffix' | 'segment' | 'regex' | 'traversal';
}

function isGuarded(rule: Rule, path: string): boolean {
  if (!rule.falsePositiveGuards || rule.falsePositiveGuards.length === 0) {
    return false;
  }
  const lower = path.toLowerCase();
  for (const guard of rule.falsePositiveGuards) {
    if (typeof guard === 'string') {
      if (lower.includes(guard.toLowerCase())) {
        return true;
      }
    } else if (guard instanceof RegExp) {
      if (guard.test(path)) {
        return true;
      }
    }
  }
  return false;
}

export function isExcluded(ruleset: CompiledRuleSet, path: string): boolean {
  for (const exclusion of ruleset.exclusions) {
    if (typeof exclusion === 'string') {
      if (path.toLowerCase().startsWith(exclusion.toLowerCase())) {
        return true;
      }
    } else if (exclusion instanceof RegExp) {
      if (exclusion.test(path)) {
        return true;
      }
    }
  }
  return false;
}

export class MatcherEngine {
  private ruleset: CompiledRuleSet;

  constructor(ruleset: CompiledRuleSet) {
    this.ruleset = ruleset;
  }

  public match(norm: NormalizationResult): MatchResult {
    const { normalizedPath, rawPath, traversalDetected } = norm;
    const lower = normalizedPath.toLowerCase();

    // 1. Path traversal check
    if (traversalDetected) {
      // Find matching traversal segment or default traversal rule
      for (const [segment, rule] of this.ruleset.segment) {
        if (lower.includes(segment)) {
          return { matched: true, rule, matchType: 'segment' };
        }
      }
      return {
        matched: true,
        rule: {
          id: 'path-traversal-detected',
          category: 'path-traversal',
          severity: 'critical',
          match: { type: 'segment', value: '..' },
          description: 'Path traversal sequence detected in request'
        },
        matchType: 'traversal'
      };
    }

    // 2. Check exclusions for clean static assets / doc paths
    if (isExcluded(this.ruleset, normalizedPath) || isExcluded(this.ruleset, rawPath)) {
      return { matched: false };
    }

    // 3. Exact match - O(1) Map lookup
    const exactRule = this.ruleset.exact.get(lower);
    if (exactRule) {
      if (!isGuarded(exactRule, rawPath) && !isGuarded(exactRule, normalizedPath)) {
        return { matched: true, rule: exactRule, matchType: 'exact' };
      }
    }

    // 4. Prefix match - O(k) Trie lookup
    const prefixRule = matchPrefixTrie(this.ruleset.prefixTrie, lower);
    if (prefixRule) {
      if (!isGuarded(prefixRule, rawPath) && !isGuarded(prefixRule, normalizedPath)) {
        return { matched: true, rule: prefixRule, matchType: 'prefix' };
      }
    }

    // 5. Segment match
    for (const [seg, segRule] of this.ruleset.segment) {
      if (lower.includes(seg)) {
        if (!isGuarded(segRule, rawPath) && !isGuarded(segRule, normalizedPath)) {
          return { matched: true, rule: segRule, matchType: 'segment' };
        }
      }
    }

    // 6. Suffix / Extension match
    for (const [ext, sufRule] of this.ruleset.suffix) {
      if (lower.endsWith(ext)) {
        if (!isGuarded(sufRule, rawPath) && !isGuarded(sufRule, normalizedPath)) {
          return { matched: true, rule: sufRule, matchType: 'suffix' };
        }
      }
    }

    // 7. Regex fallback
    for (const { pattern, rule } of this.ruleset.regex) {
      if (pattern.test(normalizedPath) || pattern.test(rawPath)) {
        if (!isGuarded(rule, rawPath) && !isGuarded(rule, normalizedPath)) {
          return { matched: true, rule, matchType: 'regex' };
        }
      }
    }

    return { matched: false };
  }
}
