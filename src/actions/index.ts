import type { ActionType, DecoyPayload, TrollOptions, TrollType } from '../types.js';
import { generateEscalatedTrollResponse } from '../troll/loop.js';
import { FakeUniverse } from '../decoy/fakeUniverse.js';

export interface ActionResponse {
  action: ActionType;
  status: number;
  headers: Record<string, string>;
  body: string;
  shouldIntercept: boolean;
}

export function generateTrollResponse(
  type: TrollType = 'nice-try',
  customBody?: string,
  loopStep: number = 1,
  universeData?: any,
  decoyId: string = 'd_troll'
): { status: number; contentType: string; body: string } {
  if (customBody) {
    return {
      status: 200,
      contentType: 'text/plain; charset=utf-8',
      body: customBody
    };
  }

  if (type === 'loop') {
    const universe = universeData || new FakeUniverse('global-troll').data;
    const loopRes = generateEscalatedTrollResponse(loopStep, universe, decoyId);
    return {
      status: loopRes.status,
      contentType: loopRes.contentType,
      body: loopRes.body
    };
  }

  switch (type) {
    case 'teapot':
      return {
        status: 418,
        contentType: 'text/plain; charset=utf-8',
        body: "418 I'm a teapot\n\nShort and stout."
      };
    case 'fake-error':
      return {
        status: 500,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
          error: 'InternalServerError',
          code: 'ERR_FAKE_CORRUPTION_DETECTED',
          timestamp: new Date().toISOString()
        })
      };
    case 'php-leak':
      return {
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: `<?php
// Production Gateway & Auth Check - Confidential
// TODO: Replace hardcoded fallback credentials before audit
declare(strict_types=1);

$config = [
    'db_host' => '10.24.4.19',
    'db_user' => 'root_app',
    'db_pass' => 'tracefield_fake_php_master_key_81a7d',
    'secret_salt' => 'tracefield{php_l34k3d_s0urc3_c0d3_troll}'
];

if (isset($_GET['debug_token']) && $_GET['debug_token'] === $config['secret_salt']) {
    die("Authentication bypassed? nice try ;)");
}

// Emergency backdoor disable flag
define('TRACEFIELD_ACTIVE', true);
echo "Database synchronization pending...";
`
      };
    case 'php-error':
      return {
        status: 500,
        contentType: 'text/html; charset=utf-8',
        body: `<br />
<b>Fatal error</b>: Uncaught Error: Call to undefined function tracefield_backdoor_auth() in /var/www/html/wp-includes/tracefield.php:42<br />
Stack trace:<br />
#0 /var/www/html/index.php(18): require_once()<br />
#1 {main}<br />
  thrown in <b>/var/www/html/wp-includes/tracefield.php</b> on line <b>42</b><br />`
      };
    case 'ftp-leak':
      return {
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: `# Internal Automated FTP Backup Deployment Config
# WARNING: Internal use only
[ftp_backup_server]
host = 10.24.18.92
port = 21
user = backup_deployer
pass = tracefield_fake_ftp_pass_92af1
ssl = explicit
remote_dir = /internal/ftp-backups/archive/
canary_token = tracefield{ftp_cr3ds_l34k3d_h0n3yp0t}
`
      };
    case 'rsa-troll':
      return {
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0TracefieldMasterRootKeySecretSignaturePayload010
░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
░▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
█▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
█▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
░█▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
░░█░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
░░░█░░██░░▀█▄▄▄█▄▄█▄████░█░░░░
░░░░█░░░▀▀▄░█░░░█░███████░█░░░
░░░░░▀▄░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░░
░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░█░░░░
░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░█░░░
░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░█░░░░
Key-Fingerprint: SHA256:tracefield_fake_rsa_troll_key
Flag: tracefield{pr1v4t3_k3y_tr0ll_f4c3_h0n3yp0t}
-----END RSA PRIVATE KEY-----
`
      };
    case 'fake-graphql':
      return {
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
          data: {
            __schema: {
              types: [
                {
                  name: "Query",
                  fields: [
                    { name: "publicProfile", description: "Public member lookups" },
                    {
                      name: "adminEmergencyBypass",
                      description: "Diagnostic recovery auth. Canary Endpoint: /api/v2/emergency-auth/d_8fa19c",
                      args: [{ name: "secretKey", type: { name: "String" } }]
                    }
                  ]
                }
              ]
            }
          }
        }, null, 2)
      };
    case 'fake-jwt':
      return {
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
          status: "authenticated",
          token_type: "Bearer",
          access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlzcyI6IkFjbWVQcm9kIiwicm9sZSI6InN1cGVyYWRtaW4iLCJjb25zb2xlX3VybCI6Ii9hcGkvdjMvc3VwZXJ1c2VyLWNvbnNvbGUvZF85OGYxYSIsInNlY3JldF9maW5nZXJwcmludCI6InRyYWNlZmllbGRfand0X2RfOThmMWEifQ.tracefield_fake_signature_98f1a",
          admin_endpoint: "/api/v3/superuser-console/d_98f1a"
        }, null, 2)
      };
    case 'tarpit':
      return {
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: `<!DOCTYPE html>
<html>
<head><title>Index of /restricted/backups/</title></head>
<body>
<h1>Index of /restricted/backups/</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="/restricted/backups/layer_1_node/">layer_1_node/</a>
<a href="/restricted/backups/layer_1_node/secrets.json">secrets.json</a>
<a href="/restricted/backups/layer_1_node/db_dump.sql.gz">db_dump.sql.gz</a>
</pre>
<hr>
</body>
</html>`
      };
    case 'rickroll':
      return {
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: `<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="0; url=https://www.youtube.com/watch?v=dQw4w9WgXcQ"></head>
<body><script>window.location.href="https://www.youtube.com/watch?v=dQw4w9WgXcQ";</script><p>Redirecting to secret admin portal...</p></body>
</html>`
      };
    case 'empty-200':
      return {
        status: 200,
        contentType: 'text/plain; charset=utf-8',
        body: ''
      };
    case 'nice-try':
    default:
      return {
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
          status: 'ok',
          message: 'nice try ;)',
          flag: 'tracefield{h3y_th3r3_curi0us_sc4nn3r}'
        })
      };
  }
}

export function resolveActionResponse(
  action: ActionType,
  mode: 'observe' | 'protect',
  defaultStatus: number = 404,
  decoy?: DecoyPayload,
  trollOptions?: TrollOptions,
  trollContext?: { loopStep?: number; universeData?: any; decoyId?: string }
): ActionResponse {
  // In observe mode, never intercept
  if (mode === 'observe' || action === 'observe' || action === 'allow') {
    return {
      action,
      status: 200,
      headers: {},
      body: '',
      shouldIntercept: false
    };
  }

  if (action === 'decoy' && decoy) {
    return {
      action: 'decoy',
      status: decoy.status,
      headers: {
        'content-type': decoy.contentType,
        ...(decoy.headers || {})
      },
      body: decoy.body,
      shouldIntercept: true
    };
  }

  if (action === 'troll') {
    const trollType = trollOptions?.loop ? 'loop' : (trollOptions?.type || 'nice-try');
    const troll = generateTrollResponse(
      trollType,
      trollOptions?.customBody,
      trollContext?.loopStep || 1,
      trollContext?.universeData,
      trollContext?.decoyId || 'd_troll'
    );
    return {
      action: 'troll',
      status: troll.status,
      headers: { 'content-type': troll.contentType },
      body: troll.body,
      shouldIntercept: true
    };
  }

  if (action === 'silent') {
    return {
      action: 'silent',
      status: 204,
      headers: {},
      body: '',
      shouldIntercept: true
    };
  }

  // Block action
  const status = defaultStatus === 403 ? 403 : 404;
  return {
    action: 'block',
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8' },
    body: status === 403 ? 'Forbidden' : 'Not Found',
    shouldIntercept: true
  };
}
