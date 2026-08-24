import type { DecoyOptions, DecoyPayload, DecoyRecord, StorageAdapter } from '../types.js';
import type { Rule } from '../rules/types.js';
import { FakeUniverse } from './fakeUniverse.js';
import {
  generateAwsCredentialsDecoy,
  generateDatabaseYmlDecoy,
  generateDotenvDecoy,
  generateFtpDecoy,
  generateGitConfigDecoy,
  generatePhpInfoDecoy,
  generateRsaKeyDecoy,
  generateSqlBackupDecoy,
  generateWpConfigDecoy,
  type DecoyTemplateResult
} from './templates.js';

import { MemoryStore } from '../session/memoryStore.js';

let counter = 0;
function generateDecoyId(): string {
  counter = (counter + 1) % 1000000;
  const rand = Math.random().toString(16).substring(2, 6);
  return `d_${Date.now().toString(36).slice(-4)}${rand}`;
}

export class DecoyEngine {
  private options: DecoyOptions;
  private storage: StorageAdapter;
  private universeCache = new Map<string, FakeUniverse>();

  constructor(options: DecoyOptions = {}, storage?: StorageAdapter) {
    this.options = {
      enabled: options.enabled ?? true,
      perScanner: options.perScanner ?? true,
      maxDepth: options.maxDepth ?? 3,
      ...options
    };
    this.storage = storage || new MemoryStore();
  }

  public getUniverseForScanner(scannerId: string): FakeUniverse {
    const key = this.options.perScanner ? scannerId : (this.options.seed || 'global-universe');
    let universe = this.universeCache.get(key);
    if (!universe) {
      universe = new FakeUniverse(key);
      this.universeCache.set(key, universe);
    }
    return universe;
  }

  public async generateDecoy(
    path: string,
    scannerId: string,
    rule?: Rule,
    parentDecoy?: DecoyRecord
  ): Promise<DecoyPayload | undefined> {
    if (this.options.enabled === false) {
      return undefined;
    }

    const currentDepth = parentDecoy ? parentDecoy.depth + 1 : 1;
    const maxDepth = this.options.maxDepth ?? 3;

    if (currentDepth > maxDepth) {
      return undefined;
    }

    const universe = this.getUniverseForScanner(scannerId);
    const decoyId = generateDecoyId();
    const lowerPath = path.toLowerCase();
    const category = rule?.category || '';

    let templateResult: DecoyTemplateResult;

    if (category === 'dotenv' || lowerPath.includes('.env')) {
      templateResult = generateDotenvDecoy(universe.data, decoyId);
    } else if (category === 'secrets' && lowerPath.includes('aws')) {
      templateResult = generateAwsCredentialsDecoy(universe.data, decoyId);
    } else if (
      lowerPath.includes('id_rsa') ||
      lowerPath.includes('id_dsa') ||
      lowerPath.includes('id_ed25519') ||
      lowerPath.includes('.ssh') ||
      lowerPath.includes('server.key') ||
      lowerPath.includes('privkey.pem') ||
      lowerPath.includes('cert.key')
    ) {
      templateResult = generateRsaKeyDecoy(universe.data, decoyId);
    } else if (category === 'wordpress' || lowerPath.includes('wp-config')) {
      templateResult = generateWpConfigDecoy(universe.data, decoyId);
    } else if (lowerPath.includes('database.yml') || lowerPath.includes('database.yaml')) {
      templateResult = generateDatabaseYmlDecoy(universe.data, decoyId);
    } else if (category === 'git' || lowerPath.includes('.git')) {
      templateResult = generateGitConfigDecoy(universe.data, decoyId);
    } else if (lowerPath.includes('ftp') || lowerPath.includes('filezilla') || lowerPath.includes('.netrc')) {
      templateResult = generateFtpDecoy(universe.data, decoyId);
    } else if (category === 'database' || lowerPath.endsWith('.sql') || lowerPath.includes('dump') || lowerPath.includes('backup')) {
      templateResult = generateSqlBackupDecoy(universe.data, decoyId);
    } else if (category === 'php' || lowerPath.includes('info.php') || lowerPath.includes('phpinfo')) {
      templateResult = generatePhpInfoDecoy(universe.data, decoyId);
    } else {
      templateResult = generateDotenvDecoy(universe.data, decoyId);
    }

    const decoyRecord: DecoyRecord = {
      decoyId,
      scannerId,
      sourcePath: path,
      canaryPaths: templateResult.canaryPaths,
      parentDecoyId: parentDecoy?.decoyId,
      createdAt: Date.now(),
      depth: currentDepth
    };

    await this.storage.saveDecoy(decoyRecord);

    return {
      decoyId,
      status: 200,
      contentType: templateResult.contentType,
      body: templateResult.body,
      canaryPaths: templateResult.canaryPaths
    };
  }
}
