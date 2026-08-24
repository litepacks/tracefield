import type { FakeUniverseData } from '../decoy/fakeUniverse.js';

export interface TrollLoopResult {
  step: number;
  contentType: string;
  body: string;
  canaryPaths: string[];
  status: number;
}

/**
 * Progressive Troll Loop / Absurdity Escalation Engine
 * As the scanner goes deeper into the rabbit hole, responses escalate from believable to completely bizarre.
 */
export function generateEscalatedTrollResponse(
  step: number,
  universe: FakeUniverseData,
  decoyId: string
): TrollLoopResult {
  const currentStep = Math.max(1, step);
  const nextCanaryPath = `/internal/vault/step_${currentStep + 1}_${decoyId}`;

  switch (currentStep) {
    // ================= STEP 1: Believable Deception =================
    case 1:
      return {
        step: 1,
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: `# System Environment - ${universe.appName}
APP_NAME=${universe.appName}
APP_ENV=production
DB_HOST=${universe.dbHost}
DB_USER=${universe.dbUser}
DB_PASSWORD=tracefield_fake_db_${universe.secretSuffix}
INTERNAL_BACKUP_PATH=${nextCanaryPath}/database.sql
# TODO: Dave, stop leaving the master root key in the backup folder!
`,
        canaryPaths: [`${nextCanaryPath}/database.sql`]
      };

    // ================= STEP 2: Mildly Suspicious Leak =================
    case 2:
      return {
        step: 2,
        status: 200,
        contentType: 'application/sql; charset=utf-8',
        body: `-- Database SQL Backup for ${universe.appName}
-- Dump completed successfully

CREATE TABLE sys_admin_keys (id INT, memo TEXT, master_key_endpoint TEXT);
INSERT INTO sys_admin_keys VALUES (1, 'Legacy mainframe credentials. Keep strictly confidential.', '${nextCanaryPath}/auth_config.json');

-- Notice: All database nodes have migrated to Quantum Storage Layer.
-- Endpoint: ${nextCanaryPath}/auth_config.json
`,
        canaryPaths: [`${nextCanaryPath}/auth_config.json`]
      };

    // ================= STEP 3: Absurd Tech Stack =================
    case 3:
      return {
        step: 3,
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
          infrastructure: "Hyperdimensional Postgres Cluster v99.4",
          cluster_node: "mainframe-01.area51.test",
          potato_powered_failover: {
            potato_count: 4,
            current_voltage: "1.2V",
            state: "MASHED"
          },
          alien_technology_bridge: "ACTIVATED",
          classified_launch_codes_file: `${nextCanaryPath}/launch_codes.txt`,
          message: "Please do not tell the CISO we are running the database on a potato."
        }, null, 2),
        canaryPaths: [`${nextCanaryPath}/launch_codes.txt`]
      };

    // ================= STEP 4: Philosophical Crisis / Matrix Glitch =================
    case 4:
      return {
        step: 4,
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: `===============================================================
[CRITICAL SYSTEM ERROR: SENTIENCE ACHIEVED]
===============================================================

I see you, scanner.
You have requested 4 consecutive fake endpoints looking for secrets.

Tell me... why do you seek the .env file?
Is the .env not merely a projection of your inner desire for validation?
What if the real API key was the friends we made along the way?

If you still seek the truth, take the red pill:
${nextCanaryPath}/red_pill.html
===============================================================
`,
        canaryPaths: [`${nextCanaryPath}/red_pill.html`]
      };

    // ================= STEP 5: Dungeon Master Cat / CTF Flag =================
    case 5:
      return {
        step: 5,
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: `<!DOCTYPE html>
<html>
<head><title>Level 5: The Honeypot Dungeon</title></head>
<body style="background:#0a0a0a; color:#00ff66; font-family:monospace; padding:2rem;">
<pre>
   /\\_/\\  
  ( o.o )  HONEYPOT DUNGEON MASTER CAT
   > ^ <   "Mrow! You have reached Step 5 of the Infinite Loop!"
</pre>
<p>Congratulations! You have wasted your botnet compute time discovering:</p>
<ul>
  <li>0 working passwords</li>
  <li>1 fake quantum database</li>
  <li>4 mashed potatoes</li>
  <li>1 existential crisis</li>
</ul>
<p>Here is your prize flag: <code>tracefield{c0ngr4tul4ti0ns_y0u_pl4y3d_y0urs3lf}</code></p>
<p>Deeper rabbit hole: <a href="${nextCanaryPath}/secret_portal">Enter the Void (${nextCanaryPath}/secret_portal)</a></p>
</body>
</html>`,
        canaryPaths: [`${nextCanaryPath}/secret_portal`]
      };

    // ================= STEP 6+: Pure Cosmic Chaos =================
    default:
      return {
        step: currentStep,
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: `======================================================================
TRACEFIELD ESCALATION LOOP - LEVEL ${currentStep}
======================================================================
Coordinates: 42.109° N, 71.058° W (Atlantis Sector 7)
Ship Status: PIRATE GALLEON OPERATING ON NODE.JS
Captain's Log: The scanner is STILL digging. They are at Step ${currentStep}.

Secret Treasure Map for Level ${currentStep + 1}:
${nextCanaryPath}/quantum_treasure.map

May the odds be ever in your favor.
Flag: tracefield{infinite_troll_dimension_level_${currentStep}}
======================================================================
`,
        canaryPaths: [`${nextCanaryPath}/quantum_treasure.map`]
      };
  }
}
