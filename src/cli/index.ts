import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { cac } from 'cac';
import { LogAnalyzer } from '../analyzer/analyzer.js';
import { inspect } from '../detector.js';

export async function runCli(argv: string[] = process.argv): Promise<void> {
  const cli = cac('tracefield');

  cli
    .command('analyze <file>', 'Analyze Nginx or Apache access logs for scanner probes')
    .option('--json', 'Output analysis in JSON format')
    .action(async (filePath: string, options: { json?: boolean }) => {
      if (!fs.existsSync(filePath)) {
        console.error(`Error: File not found at '${filePath}'`);
        process.exit(1);
      }

      const fileStream = fs.createReadStream(filePath, { encoding: 'utf-8' });
      const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

      const lines: string[] = [];
      for await (const line of rl) {
        if (line.trim()) {
          lines.push(line);
        }
      }

      const analyzer = new LogAnalyzer();
      const summary = await analyzer.analyzeLines(lines);

      if (options.json) {
        console.log(JSON.stringify(summary, null, 2));
      } else {
        console.log(analyzer.formatReport(summary));
      }
    });

  cli
    .command('test-path <path>', 'Test how a URL path is normalized, matched, and scored')
    .action(async (testPath: string) => {
      const result = await inspect({ path: testPath });
      console.log('--- tracefield path test ---');
      console.log(`Path:       ${result.rawPath}`);
      console.log(`Normalized: ${result.normalizedPath}`);
      console.log(`Matched:    ${result.matched}`);
      console.log(`Category:   ${result.category || 'none'}`);
      console.log(`Rule:       ${result.rule || 'none'}`);
      console.log(`Severity:   ${result.severity || 'none'}`);
      console.log(`Confidence: ${result.confidence}/100`);
      console.log('');
      console.log(result.explain());
    });

  cli.help();
  cli.version('1.0.0');

  // Parse args
  cli.parse(argv);
}

export default runCli;
