import { describe, expect, it, vi } from 'vitest';
import { tracefieldExpress } from '../src/adapters/express.js';
import { tracefieldHono } from '../src/adapters/hono.js';
import { tracefieldCloudflare } from '../src/adapters/cloudflare.js';

describe('Framework Adapters', () => {
  describe('Express Adapter', () => {
    it('observes and passes request to next() in observe mode', async () => {
      const middleware = tracefieldExpress({ mode: 'observe' });

      const req: any = {
        path: '/.env',
        method: 'GET',
        headers: {},
        ip: '127.0.0.1'
      };

      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn()
      };

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.tracefield).toBeDefined();
      expect(req.tracefield.matched).toBe(true);
      expect(res.send).not.toHaveBeenCalled();
    });

    it('intercepts and blocks sensitive request in protect mode', async () => {
      const middleware = tracefieldExpress({
        mode: 'protect',
        action: 'block',
        responseStatus: 404
      });

      const req: any = {
        path: '/.git/config',
        method: 'GET',
        headers: {},
        ip: '127.0.0.1'
      };

      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn()
      };

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.send).toHaveBeenCalledWith('Not Found');
    });

    it('serves fake decoy in protect mode with decoy action', async () => {
      const middleware = tracefieldExpress({
        mode: 'protect',
        action: 'decoy',
        decoy: { enabled: true }
      });

      const req: any = {
        path: '/.env',
        method: 'GET',
        headers: {},
        ip: '127.0.0.1'
      };

      let sentBody = '';
      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn((body) => {
          sentBody = body;
        })
      };

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(sentBody).toContain('APP_NAME=');
    });

    it('serves troll responses when action is set to troll', async () => {
      const middleware = tracefieldExpress({
        mode: 'protect',
        action: 'troll',
        troll: { type: 'teapot' }
      });

      const req: any = { path: '/.env', method: 'GET', headers: {}, ip: '127.0.0.1' };
      let sentBody = '';
      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn((body) => { sentBody = body; })
      };

      await middleware(req, res, vi.fn());

      expect(res.status).toHaveBeenCalledWith(418);
      expect(sentBody).toContain("418 I'm a teapot");
    });

    it('serves php-leak troll responses', async () => {
      const middleware = tracefieldExpress({
        mode: 'protect',
        action: 'troll',
        troll: { type: 'php-leak' }
      });

      const req: any = { path: '/config.php.bak', method: 'GET', headers: {}, ip: '127.0.0.1' };
      let sentBody = '';
      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn((body) => { sentBody = body; })
      };

      await middleware(req, res, vi.fn());

      expect(res.status).toHaveBeenCalledWith(200);
      expect(sentBody).toContain('<?php');
      expect(sentBody).toContain('tracefield_fake_php_master_key');
    });

    it('serves ftp-leak troll responses', async () => {
      const middleware = tracefieldExpress({
        mode: 'protect',
        action: 'troll',
        troll: { type: 'ftp-leak' }
      });

      const req: any = { path: '/ftp.txt', method: 'GET', headers: {}, ip: '127.0.0.1' };
      let sentBody = '';
      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn((body) => { sentBody = body; })
      };

      await middleware(req, res, vi.fn());

      expect(res.status).toHaveBeenCalledWith(200);
      expect(sentBody).toContain('[ftp_backup_server]');
      expect(sentBody).toContain('tracefield_fake_ftp_pass_');
    });

    it('serves rsa-troll responses with ASCII troll face', async () => {
      const middleware = tracefieldExpress({
        mode: 'protect',
        action: 'troll',
        troll: { type: 'rsa-troll' }
      });

      const req: any = { path: '/server.key', method: 'GET', headers: {}, ip: '127.0.0.1' };
      let sentBody = '';
      const res: any = {
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn(),
        send: vi.fn((body) => { sentBody = body; })
      };

      await middleware(req, res, vi.fn());

      expect(res.status).toHaveBeenCalledWith(200);
      expect(sentBody).toContain('-----BEGIN RSA PRIVATE KEY-----');
      expect(sentBody).toContain('░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░');
      expect(sentBody).toContain('tracefield{pr1v4t3_k3y_tr0ll_f4c3_h0n3yp0t}');
    });
  });

  describe('Hono Adapter', () => {
    it('returns intercepted Response for blocked request in protect mode', async () => {
      const middleware = tracefieldHono({
        mode: 'protect',
        action: 'block',
        responseStatus: 403
      });

      const req = new Request('http://localhost/.env', {
        headers: { 'user-agent': 'sqlmap/1.0' }
      });

      const ctx: any = {
        req: {
          url: 'http://localhost/.env',
          header: (h: string) => req.headers.get(h),
          raw: req
        },
        set: vi.fn()
      };

      const next = vi.fn();
      const response = await middleware(ctx, next);

      expect(next).not.toHaveBeenCalled();
      expect(response).toBeInstanceOf(Response);
      expect(response?.status).toBe(403);
    });

    it('passes normal request through to next()', async () => {
      const middleware = tracefieldHono({ mode: 'observe' });

      const req = new Request('http://localhost/api/v1/posts', {
        headers: {}
      });

      const ctx: any = {
        req: {
          url: 'http://localhost/api/v1/posts',
          header: (h: string) => req.headers.get(h),
          raw: req
        },
        set: vi.fn()
      };

      const next = vi.fn();
      await middleware(ctx, next);

      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('Cloudflare Workers Adapter', () => {
    it('serves intercepted response for blocked paths', async () => {
      const handler = vi.fn();
      const wrapped = tracefieldCloudflare(handler, {
        mode: 'protect',
        action: 'block',
        responseStatus: 404
      });

      const req = new Request('http://localhost/.git/HEAD');
      const response = await wrapped(req, {}, {});

      expect(handler).not.toHaveBeenCalled();
      expect(response.status).toBe(404);
    });

    it('forwards safe requests to the origin handler', async () => {
      const mockResponse = new Response('origin response', { status: 200 });
      const handler = vi.fn().mockResolvedValue(mockResponse);
      const wrapped = tracefieldCloudflare(handler, { mode: 'protect', action: 'block' });

      const req = new Request('http://localhost/health');
      const response = await wrapped(req, {}, {});

      expect(handler).toHaveBeenCalledTimes(1);
      expect(response).toBe(mockResponse);
    });
  });
});
