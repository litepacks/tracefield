export interface NormalizationResult {
  rawPath: string;
  normalizedPath: string;
  encodingDepth: number;
  traversalDetected: boolean;
  hasNullByte: boolean;
  suspiciousChars: boolean;
}

/**
 * Iteratively decodes percent-encoded characters while tracking decoding depth.
 * Protects against infinite decoding loops and multi-encoding evasion.
 */
function decodeMultiLayer(path: string, maxLayers = 5): { decoded: string; depth: number } {
  let current = path;
  let depth = 0;

  for (let i = 0; i < maxLayers; i++) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) {
        break;
      }
      depth++;
      current = next;
    } catch {
      // If malformed percent encoding occurs (e.g. %E0%A4), attempt partial manual replacement
      const partial = current.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
        try {
          return String.fromCharCode(parseInt(hex, 16));
        } catch {
          return match;
        }
      });
      if (partial !== current) {
        depth++;
        current = partial;
      }
      break;
    }
  }

  return { decoded: current, depth };
}

/**
 * Resolves standard POSIX dot segments (/./ and /../)
 */
function resolveDotSegments(path: string): string {
  const segments = path.split('/');
  const resolved: string[] = [];

  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      continue;
    }
    if (segment === '..') {
      if (resolved.length > 0) {
        resolved.pop();
      }
    } else {
      resolved.push(segment);
    }
  }

  return '/' + resolved.join('/');
}

/**
 * Normalizes an incoming raw URL or request path.
 */
export function normalizePath(inputPath: string): NormalizationResult {
  const rawPath = inputPath || '/';

  // 1. Strip query parameters and fragment identifier
  let working = rawPath.split('?')[0].split('#')[0];

  // Check for null bytes before stripping
  const hasNullByte = working.includes('\0') || working.includes('%00') || working.includes('%0');
  if (hasNullByte) {
    working = working.replace(/\0|%00|%0/g, '');
  }

  // 2. Multi-layer URL decoding
  const { decoded, depth } = decodeMultiLayer(working);
  working = decoded;

  // 3. Normalize backslashes to forward slashes
  working = working.replace(/\\+/g, '/');

  // 4. Detect path traversal attempts before dot resolution
  const traversalDetected =
    /\.\.\//.test(working) ||
    /\/\.\./.test(working) ||
    working.includes('/..') ||
    working.startsWith('..') ||
    rawPath.includes('%2e%2e') ||
    rawPath.includes('%2E%2E') ||
    rawPath.includes('%252e%252e');

  // Check for suspicious characters (control characters, special delimiters)
  const suspiciousChars =
    hasNullByte ||
    /[\x00-\x1F\x7F<>"'`|*]/.test(working) ||
    depth > 1;

  // 5. Collapse duplicate slashes
  working = working.replace(/\/+/g, '/');

  // 6. Ensure leading slash
  if (!working.startsWith('/')) {
    working = '/' + working;
  }

  // 7. Resolve dot segments
  const normalizedPath = resolveDotSegments(working);

  return {
    rawPath,
    normalizedPath,
    encodingDepth: depth,
    traversalDetected,
    hasNullByte,
    suspiciousChars
  };
}
