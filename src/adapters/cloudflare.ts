import type { DetectorOptions, HttpRequest } from '../types.js';
import { createDetector, Detector } from '../detector.js';

export function tracefieldCloudflare(
  handlerOrOptions?: ((request: Request, env: any, ctx: any) => Promise<Response>) | DetectorOptions | Detector,
  optionsOrDetector?: DetectorOptions | Detector
) {
  let handler: ((request: Request, env: any, ctx: any) => Promise<Response>) | undefined;
  let detector: Detector;

  if (typeof handlerOrOptions === 'function') {
    handler = handlerOrOptions;
    detector = optionsOrDetector instanceof Detector ? optionsOrDetector : createDetector(optionsOrDetector);
  } else {
    detector = handlerOrOptions instanceof Detector ? handlerOrOptions : createDetector(handlerOrOptions);
  }

  return async function fetchWithTracefield(
    request: Request,
    env: any = {},
    ctx: any = {}
  ): Promise<Response> {
    try {
      const url = new URL(request.url);
      const clientIp =
        request.headers.get('cf-connecting-ip') ||
        request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
        '127.0.0.1';

      const headers: Record<string, string> = {};
      request.headers.forEach((val, key) => {
        headers[key] = val;
      });

      const httpReq: HttpRequest = {
        path: url.pathname,
        rawUrl: request.url,
        method: request.method,
        headers,
        ip: clientIp
      };

      const result = await detector.inspect(httpReq);
      const actionResponse = detector.resolveResponse(result);

      if (actionResponse.shouldIntercept) {
        return new Response(actionResponse.body, {
          status: actionResponse.status,
          headers: actionResponse.headers
        });
      }

      if (handler) {
        return await handler(request, env, ctx);
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      console.error('[tracefield/cloudflare] Handler error:', err);
      if (handler) {
        return await handler(request, env, ctx);
      }
      return new Response('Internal Error', { status: 500 });
    }
  };
}

export const tracefield = tracefieldCloudflare;
export default tracefieldCloudflare;
