import type { FakeUniverseData } from '../decoy/fakeUniverse.js';

export interface TrapPayload {
  contentType: string;
  body: string;
  status: number;
  canaryPaths: string[];
  headers?: Record<string, string>;
}

/**
 * Generates a fake robots.txt containing honeypot trap paths.
 * Automated scanners actively crawl Disallow entries looking for hidden panels.
 */
export function generateRobotsTrap(universe: FakeUniverseData, decoyId: string): TrapPayload {
  const honeypotPath1 = `/secret-admin-vault-${decoyId}/`;
  const honeypotPath2 = `/internal-system-backup-${decoyId}/`;

  const body = `# robots.txt for ${universe.appName}
User-agent: *
Allow: /
Allow: /api/public/

# Security restricted paths - DO NOT CRAWL
Disallow: ${honeypotPath1}
Disallow: ${honeypotPath2}
Disallow: /wp-admin/
Disallow: /.env
`;

  return {
    status: 200,
    contentType: 'text/plain; charset=utf-8',
    body,
    canaryPaths: [honeypotPath1.slice(0, -1), honeypotPath2.slice(0, -1)]
  };
}

/**
 * Generates a fake GraphQL schema with honey queries.
 */
export function generateGraphQLTrap(universe: FakeUniverseData, decoyId: string): TrapPayload {
  const canaryEndpoint = `/api/v2/emergency-auth/${decoyId}`;

  const body = JSON.stringify({
    data: {
      __schema: {
        types: [
          {
            name: "Query",
            fields: [
              { name: "getUsers", description: "Public user listing" },
              { name: "systemHealth", description: "Service status" },
              {
                name: "superAdminBypass",
                description: `Emergency auth gateway. Endpoint: ${canaryEndpoint}`,
                args: [{ name: "masterKey", type: { name: "String" } }]
              }
            ]
          }
        ]
      }
    }
  }, null, 2);

  return {
    status: 200,
    contentType: 'application/json; charset=utf-8',
    body,
    canaryPaths: [canaryEndpoint]
  };
}

/**
 * Generates a fake JWT Bearer token with embedded canary paths.
 */
export function generateJwtTrap(universe: FakeUniverseData, decoyId: string): { token: string; payload: TrapPayload } {
  const canaryPath = `/api/v3/superuser-console/${decoyId}`;

  // Fake JWT header & payload
  const headerBase64 = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString('base64url');
  const payloadBase64 = Buffer.from(JSON.stringify({
    sub: "admin",
    iss: universe.appName,
    role: "super_administrator",
    console_url: canaryPath,
    secret_fingerprint: `tracefield_jwt_${decoyId}`,
    exp: Math.floor(Date.now() / 1000) + 86400
  })).toString('base64url');
  const sigBase64 = Buffer.from(`tracefield_fake_signature_${universe.secretSuffix}`).toString('base64url');

  const token = `${headerBase64}.${payloadBase64}.${sigBase64}`;

  const body = JSON.stringify({
    status: "authenticated",
    token_type: "Bearer",
    access_token: token,
    expires_in: 86400,
    admin_endpoint: canaryPath
  }, null, 2);

  return {
    token,
    payload: {
      status: 200,
      contentType: 'application/json; charset=utf-8',
      body,
      canaryPaths: [canaryPath]
    }
  };
}

/**
 * Generates an infinite deterministic recursive directory trap ("Tarpit Lite")
 * Keeps automated path fuzzers caught in recursive loops exploring fake layers.
 */
export function generateRecursiveDirTrap(path: string, universe: FakeUniverseData, decoyId: string): TrapPayload {
  const parts = path.split('/').filter(Boolean);
  const nextSegment = `layer_${parts.length + 1}_${decoyId}`;
  const nextUrl = `${path.replace(/\/$/, '')}/${nextSegment}`;

  const body = `<!DOCTYPE html>
<html>
<head><title>Index of ${path}</title></head>
<body>
<h1>Index of ${path}</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="${nextUrl}/">${nextSegment}/</a>
<a href="${nextUrl}/backup.tar.gz">backup_snapshot_${parts.length + 1}.tar.gz</a>
<a href="${nextUrl}/secrets.json">secrets_${parts.length + 1}.json</a>
</pre>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at ${universe.appName.toLowerCase()}.internal Port 80</address>
</body>
</html>`;

  return {
    status: 200,
    contentType: 'text/html; charset=utf-8',
    body,
    canaryPaths: [`${nextUrl}/backup.tar.gz`, `${nextUrl}/secrets.json`]
  };
}
