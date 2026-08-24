import type { HttpRequest } from '../types.js';

export interface ParsedLogEntry {
  ip: string;
  timestamp?: string;
  method: string;
  path: string;
  status: number;
  userAgent?: string;
  raw: string;
}

// Regex for Combined Log Format: IP - - [date] "METHOD /path HTTP/1.1" status bytes "referer" "user-agent"
const COMBINED_LOG_REGEX = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

// Regex for Common Log Format: IP - - [date] "METHOD /path HTTP/1.1" status bytes
const COMMON_LOG_REGEX = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)"\s+(\d{3})\s+(\S+)/;

export function parseLogLine(line: string): ParsedLogEntry | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) {
    return null;
  }

  let match = COMBINED_LOG_REGEX.exec(trimmed);
  if (match) {
    return {
      ip: match[1],
      timestamp: match[2],
      method: match[3],
      path: match[4],
      status: parseInt(match[5], 10),
      userAgent: match[8] || undefined,
      raw: trimmed
    };
  }

  match = COMMON_LOG_REGEX.exec(trimmed);
  if (match) {
    return {
      ip: match[1],
      timestamp: match[2],
      method: match[3],
      path: match[4],
      status: parseInt(match[5], 10),
      userAgent: undefined,
      raw: trimmed
    };
  }

  return null;
}

export function logEntryToHttpRequest(entry: ParsedLogEntry): HttpRequest {
  return {
    path: entry.path,
    rawUrl: entry.path,
    method: entry.method,
    ip: entry.ip,
    headers: entry.userAgent ? { 'user-agent': entry.userAgent } : {}
  };
}
