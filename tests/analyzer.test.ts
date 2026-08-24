import { describe, expect, it } from 'vitest';
import { LogAnalyzer } from '../src/analyzer/analyzer.js';
import { parseLogLine } from '../src/analyzer/parser.js';

describe('Access Log Analyzer', () => {
  it('parses combined and common log lines correctly', () => {
    const combinedLine = '198.51.100.5 - - [23/Aug/2026:14:32:10 +0000] "GET /.env HTTP/1.1" 404 152 "-" "Go-http-client/1.1"';
    const parsed = parseLogLine(combinedLine);

    expect(parsed).toBeDefined();
    expect(parsed?.ip).toBe('198.51.100.5');
    expect(parsed?.method).toBe('GET');
    expect(parsed?.path).toBe('/.env');
    expect(parsed?.status).toBe(404);
    expect(parsed?.userAgent).toBe('Go-http-client/1.1');
  });

  it('aggregates log statistics and identifies scanners', async () => {
    const lines = [
      '198.51.100.1 - - [23/Aug/2026:14:00:01 +0000] "GET / HTTP/1.1" 200 4500 "-" "Mozilla/5.0"',
      '198.51.100.1 - - [23/Aug/2026:14:00:02 +0000] "GET /about HTTP/1.1" 200 3200 "-" "Mozilla/5.0"',
      '198.51.100.8 - - [23/Aug/2026:14:00:03 +0000] "GET /.env HTTP/1.1" 404 150 "-" "curl/7.68.0"',
      '198.51.100.8 - - [23/Aug/2026:14:00:04 +0000] "GET /.git/config HTTP/1.1" 404 150 "-" "curl/7.68.0"',
      '198.51.100.8 - - [23/Aug/2026:14:00:05 +0000] "GET /wp-login.php HTTP/1.1" 404 150 "-" "curl/7.68.0"',
      '198.51.100.9 - - [23/Aug/2026:14:00:06 +0000] "GET /database.sql HTTP/1.1" 404 150 "-" "python-requests/2.25.1"'
    ];

    const analyzer = new LogAnalyzer();
    const summary = await analyzer.analyzeLines(lines);

    expect(summary.requestsAnalyzed).toBe(6);
    expect(summary.probeRequests).toBe(4);
    expect(summary.topCategories['dotenv']).toBe(1);
    expect(summary.topCategories['git']).toBe(1);
    expect(summary.topCategories['wordpress']).toBe(1);
    expect(summary.topCategories['database']).toBe(1);

    const report = analyzer.formatReport(summary);
    expect(report).toContain('Requests analyzed: 6');
    expect(report).toContain('Probe requests:    4');
    expect(report).toContain('dotenv');
  });
});
