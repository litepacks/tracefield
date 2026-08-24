import { createDetector, Detector } from '../detector.js';
import { logEntryToHttpRequest, parseLogLine } from './parser.js';

export interface AnalysisSummary {
  requestsAnalyzed: number;
  probeRequests: number;
  likelyScanners: number;
  confirmedScanners: number;
  topCategories: Record<string, number>;
  topScannerIps: { ip: string; probes: number; confidence: number }[];
  scanners: {
    scannerId: string;
    ip: string;
    probes: number;
    confidence: number;
    categories: string[];
  }[];
}

export class LogAnalyzer {
  private detector: Detector;

  constructor(customDetector?: Detector) {
    this.detector = customDetector || createDetector({ mode: 'observe' });
  }

  public async analyzeLines(lines: string[]): Promise<AnalysisSummary> {
    let requestsAnalyzed = 0;
    let probeRequests = 0;
    const categoryCounts: Record<string, number> = {};
    const ipProbeCounts = new Map<string, { probes: number; confidence: number }>();
    const scannerMap = new Map<string, { ip: string; probes: number; confidence: number; categories: Set<string> }>();

    for (const line of lines) {
      const entry = parseLogLine(line);
      if (!entry) continue;

      requestsAnalyzed++;
      const req = logEntryToHttpRequest(entry);
      const result = await this.detector.inspect(req);

      if (result.matched || result.confidence >= 40) {
        probeRequests++;

        const category = result.category || 'unknown';
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;

        const ipStats = ipProbeCounts.get(entry.ip) || { probes: 0, confidence: 0 };
        ipStats.probes++;
        ipStats.confidence = Math.max(ipStats.confidence, result.confidence);
        ipProbeCounts.set(entry.ip, ipStats);

        if (result.session) {
          const sc = scannerMap.get(result.session.scannerId) || {
            ip: entry.ip,
            probes: 0,
            confidence: 0,
            categories: new Set<string>()
          };
          sc.probes++;
          sc.confidence = Math.max(sc.confidence, result.confidence);
          if (result.category) sc.categories.add(result.category);
          scannerMap.set(result.session.scannerId, sc);
        }
      }
    }

    let likelyScanners = 0;
    let confirmedScanners = 0;

    for (const [, stats] of ipProbeCounts.entries()) {
      if (stats.confidence >= 90) {
        confirmedScanners++;
      } else if (stats.confidence >= 70) {
        likelyScanners++;
      }
    }

    const topScannerIps = Array.from(ipProbeCounts.entries())
      .map(([ip, stats]) => ({ ip, probes: stats.probes, confidence: stats.confidence }))
      .sort((a, b) => b.probes - a.probes)
      .slice(0, 10);

    const scanners = Array.from(scannerMap.entries()).map(([scannerId, sc]) => ({
      scannerId,
      ip: sc.ip,
      probes: sc.probes,
      confidence: sc.confidence,
      categories: Array.from(sc.categories)
    }));

    return {
      requestsAnalyzed,
      probeRequests,
      likelyScanners,
      confirmedScanners,
      topCategories: categoryCounts,
      topScannerIps,
      scanners
    };
  }

  public formatReport(summary: AnalysisSummary): string {
    const lines: string[] = [];
    lines.push(`Requests analyzed: ${summary.requestsAnalyzed.toLocaleString()}`);
    lines.push(`Probe requests:    ${summary.probeRequests.toLocaleString()}`);
    lines.push(`Likely scanners:   ${summary.likelyScanners.toLocaleString()}`);
    lines.push(`Confirmed scanners: ${summary.confirmedScanners.toLocaleString()}`);
    lines.push('');
    lines.push('Top categories:');

    const sortedCategories = Object.entries(summary.topCategories)
      .sort((a, b) => b[1] - a[1]);

    if (sortedCategories.length === 0) {
      lines.push('  (none)');
    } else {
      for (const [cat, count] of sortedCategories) {
        lines.push(`  ${cat.padEnd(16, ' ')} ${count.toLocaleString().padStart(6, ' ')}`);
      }
    }

    return lines.join('\n');
  }
}
