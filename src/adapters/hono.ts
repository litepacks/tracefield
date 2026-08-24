import type { DetectorOptions, HttpRequest } from '../types.js';
import { createDetector, Detector } from '../detector.js';

export function tracefieldHono(optionsOrDetector?: DetectorOptions | Detector) {
  const detector =
    optionsOrDetector instanceof Detector
      ? optionsOrDetector
      : createDetector(optionsOrDetector);

  return async function tracefieldMiddleware(
    c: any,
    next: () => Promise<void>
  ): Promise<Response | void> {
    try {
      const url = new URL(c.req.url);
      const clientIp =
        c.req.header('x-forwarded-for')?.split(',')[0].trim() ||
        c.req.header('cf-connecting-ip') ||
        '127.0.0.1';

      const headers: Record<string, string> = {};
      c.req.raw.headers.forEach((val: string, key: string) => {
        headers[key] = val;
      });

      const httpReq: HttpRequest = {
        path: url.pathname,
        rawUrl: c.req.url,
        method: c.req.method,
        headers,
        ip: clientIp
      };

      const result = await detector.inspect(httpReq);
      c.set('tracefield', result);

      const actionResponse = detector.resolveResponse(result);

      if (actionResponse.shouldIntercept) {
        return new Response(actionResponse.body, {
          status: actionResponse.status,
          headers: actionResponse.headers
        });
      }

      await next();
    } catch (err) {
      console.error('[tracefield/hono] Middleware error:', err);
      await next();
    }
  };
}

export const tracefield = tracefieldHono;
export default tracefieldHono;
