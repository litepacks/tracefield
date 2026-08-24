export type RuleCategory =
  | 'secrets'
  | 'dotenv'
  | 'git'
  | 'backups'
  | 'wordpress'
  | 'php'
  | 'database'
  | 'cloud'
  | 'framework'
  | 'admin'
  | 'debug'
  | 'source-control'
  | 'server-config'
  | 'path-traversal'
  | 'encoded-probe'
  | 'shell'
  | 'known-malware-path'
  | 'generic-fuzzing'
  | 'custom'
  | (string & {});

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export type MatchType = 'exact' | 'prefix' | 'suffix' | 'segment' | 'regex';

export interface RuleMatch {
  type: MatchType;
  value: string | RegExp;
}

export interface Rule {
  id: string;
  category: RuleCategory;
  severity: SeverityLevel;
  match: RuleMatch;
  description?: string;
  tags?: string[];
  falsePositiveGuards?: (string | RegExp)[];
}

export interface RawRule {
  id: string;
  category?: RuleCategory;
  severity?: SeverityLevel;
  match?: RuleMatch;
  path?: string;
  type?: MatchType;
  value?: string | RegExp;
  description?: string;
  tags?: string[];
  falsePositiveGuards?: (string | RegExp)[];
}

export interface PrefixTrieNode {
  children: Map<string, PrefixTrieNode>;
  rule?: Rule;
  isEnd: boolean;
}

export interface CompiledRuleSet {
  exact: Map<string, Rule>;
  prefixTrie: PrefixTrieNode;
  suffix: Map<string, Rule>;
  segment: Map<string, Rule>;
  regex: { pattern: RegExp; rule: Rule }[];
  exclusions: (string | RegExp)[];
}
