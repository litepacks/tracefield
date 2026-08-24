/**
 * Pseudo-random number generator (Mulberry32) seeded by a string or integer.
 * Ensures that the same scanner consistently receives the same fake universe details.
 */
function createSeededPrng(seedStr: string): () => number {
  let h = 0xdeadbeef;
  for (let i = 0; i < seedStr.length; i++) {
    h = Math.imul(h ^ seedStr.charCodeAt(i), 2654435761);
  }

  let s = h >>> 0;
  return function mulberry32(): number {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface FakeUniverseData {
  appName: string;
  dbHost: string;
  dbPort: number;
  dbName: string;
  dbUser: string;
  redisHost: string;
  adminDomain: string;
  awsRegion: string;
  secretSuffix: string;
}

const APP_NAMES = ['NexusCore', 'AcmeProduction', 'ApexGlobal', 'VortexAPI', 'TitanEdge', 'ZephyrServices', 'AuraCloud'];
const DB_NAMES = ['prod_main', 'app_db', 'core_production', 'main_db', 'service_prod'];
const DB_USERS = ['app_prod', 'db_admin', 'service_user', 'core_writer'];
const FAKE_APP_NAMES = ['NexusCore', 'AcmeProduction', 'ApexGlobal', 'VortexAPI', 'TitanEdge', 'ZephyrServices', 'AuraCloud'];
const FAKE_DB_NAMES = ['prod_main', 'app_db', 'core_production', 'main_db', 'service_prod'];
const FAKE_DB_USERS = ['app_prod', 'db_admin', 'service_user', 'core_writer'];
const FAKE_AWS_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'];

export class FakeUniverse {
  public data: FakeUniverseData;
  private rand: () => number;

  constructor(seed: string = 'tracefield-default-seed') {
    this.rand = createSeededPrng(seed);

    const pick = <T>(arr: T[]): T => arr[Math.floor(this.rand() * arr.length)];
    const randInt = (min: number, max: number): number => Math.floor(this.rand() * (max - min + 1)) + min;
    const hex = (len: number): string => {
      let result = '';
      const chars = '0123456789abcdef';
      for (let i = 0; i < len; i++) {
        result += chars[Math.floor(this.rand() * chars.length)];
      }
      return result;
    };

    const appName = pick(FAKE_APP_NAMES);
    const dbUser = pick(FAKE_DB_USERS);
    const dbName = pick(FAKE_DB_NAMES);
    const dbHost = `10.24.${randInt(1, 254)}.${randInt(1, 254)}`;
    const dbPort = pick([3306, 5432]);
    const redisHost = `10.24.${randInt(1, 254)}.${randInt(1, 254)}`;
    const awsRegion = pick(FAKE_AWS_REGIONS);
    const secretSuffix = hex(6);
    const adminDomain = `${appName.toLowerCase()}-internal-vault.test`;

    this.data = {
      appName,
      dbUser,
      dbName,
      dbHost,
      dbPort,
      redisHost,
      awsRegion,
      secretSuffix,
      adminDomain
    };
  }

  public getSecretToken(prefix: string = 'tracefield_fake'): string {
    return `${prefix}_${this.data.secretSuffix}`;
  }
}
