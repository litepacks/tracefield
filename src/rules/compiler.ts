import type { CompiledRuleSet, PrefixTrieNode, RawRule, Rule } from './types.js';
import { DEFAULT_EXCLUSIONS, DEFAULT_RULES } from './defaults.js';

function createTrieNode(): PrefixTrieNode {
  return {
    children: new Map(),
    isEnd: false
  };
}

function insertPrefix(root: PrefixTrieNode, prefix: string, rule: Rule): void {
  let current = root;
  const normalized = prefix.toLowerCase();
  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i];
    let next = current.children.get(char);
    if (!next) {
      next = createTrieNode();
      current.children.set(char, next);
    }
    current = next;
  }
  current.isEnd = true;
  current.rule = rule;
}

export function normalizeRawRule(raw: RawRule | Rule): Rule {
  if ('match' in raw && raw.match) {
    return {
      id: raw.id,
      category: raw.category || 'custom',
      severity: raw.severity || 'high',
      match: raw.match,
      description: raw.description,
      tags: raw.tags,
      falsePositiveGuards: raw.falsePositiveGuards
    };
  }

  const rawRule = raw as RawRule;
  const matchType = rawRule.type || 'exact';
  const matchValue = rawRule.value || rawRule.path || '';

  return {
    id: raw.id,
    category: raw.category || 'custom',
    severity: raw.severity || 'high',
    match: {
      type: matchType,
      value: matchValue
    },
    description: raw.description,
    tags: raw.tags,
    falsePositiveGuards: raw.falsePositiveGuards
  };
}

export function compileRules(
  customRules: (Rule | RawRule)[] = [],
  customExclusions: (string | RegExp)[] = []
): CompiledRuleSet {
  const exact = new Map<string, Rule>();
  const prefixTrie = createTrieNode();
  const suffix = new Map<string, Rule>();
  const segment = new Map<string, Rule>();
  const regex: { pattern: RegExp; rule: Rule }[] = [];

  const seenIds = new Set<string>();
  const allRules: Rule[] = [];

  // Add custom rules first (higher precedence)
  for (const raw of customRules) {
    const rule = normalizeRawRule(raw);
    seenIds.add(rule.id);
    allRules.push(rule);
  }

  // Add default rules if not overridden
  for (const rule of DEFAULT_RULES) {
    if (!seenIds.has(rule.id)) {
      allRules.push(rule);
    }
  }

  // Populate fast-lookup data structures
  for (const rule of allRules) {
    const { type, value } = rule.match;

    if (type === 'exact' && typeof value === 'string') {
      const key = value.toLowerCase();
      if (!exact.has(key)) {
        exact.set(key, rule);
      }
    } else if (type === 'prefix' && typeof value === 'string') {
      insertPrefix(prefixTrie, value, rule);
    } else if (type === 'suffix' && typeof value === 'string') {
      const key = value.toLowerCase();
      if (!suffix.has(key)) {
        suffix.set(key, rule);
      }
    } else if (type === 'segment' && typeof value === 'string') {
      const key = value.toLowerCase();
      if (!segment.has(key)) {
        segment.set(key, rule);
      }
    } else if (type === 'regex') {
      const pattern = typeof value === 'string' ? new RegExp(value, 'i') : value;
      regex.push({ pattern, rule });
    }
  }

  const exclusions = [...DEFAULT_EXCLUSIONS, ...customExclusions];

  return {
    exact,
    prefixTrie,
    suffix,
    segment,
    regex,
    exclusions
  };
}
