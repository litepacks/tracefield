import type { SignalBreakdown } from '../types.js';

export function formatExplain(
  confidence: number,
  breakdown: SignalBreakdown[],
  rawPath: string,
  matchedRule?: string
): string {
  const lines: string[] = [];
  lines.push(`Confidence: ${confidence}`);
  lines.push('');

  if (breakdown.length === 0) {
    lines.push('+0 No suspicious signals detected for request path: ' + rawPath);
    return lines.join('\n');
  }

  for (const item of breakdown) {
    const sign = item.points >= 0 ? `+${item.points}` : `${item.points}`;
    lines.push(`${sign.padEnd(4, ' ')} ${item.reason}`);
  }

  return lines.join('\n');
}
