import type { PrefixTrieNode, Rule } from '../rules/types.js';

export function matchPrefixTrie(root: PrefixTrieNode, path: string): Rule | undefined {
  let current: PrefixTrieNode | undefined = root;
  const lowerPath = path.toLowerCase();
  let longestMatch: Rule | undefined = undefined;

  for (let i = 0; i < lowerPath.length; i++) {
    const char = lowerPath[i];
    current = current.children.get(char);
    if (!current) {
      break;
    }
    if (current.isEnd && current.rule) {
      longestMatch = current.rule;
    }
  }

  return longestMatch;
}
