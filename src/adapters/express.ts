import type { DetectorOptions, HttpRequest, InspectionResult } from '../types.js';
import { createDetector, Detector } from '../detector.js';

export interface TracefieldExpressRequest {
  tracefield?: InspectionResult;
}

export function tracefieldExpress(
  optionsOrDetector?: DetectorOptions | Detector
) {
  const detector =
    optionsOrDetector instanceof Detector
      ? optionsOrDetector
      : createDetector(optionsOrDetector);

  return async function tracefieldMiddleware(
    req: any,
    res: any,
    next: (err?: any) => void
  ): Promise<void> {
    try {
      const fullUrl = req.originalUrl || req.url || req.path || '/';
      const parsedPath = fullUrl.split('?')[0].split('#')[0];
      const clientIp =
        req.ip ||
        (typeof req.headers?.['x-forwarded-for'] === 'string'
          ? req.headers['x-forwarded-for'].split(',')[0].trim()
          : req.socket?.remoteAddress || '127.0.0.1');

      const httpReq: HttpRequest = {
        path: parsedPath,
        rawUrl: fullUrl,
        method: req.method || 'GET',
        headers: req.headers || {},
        ip: clientIp
      };

      const result = await detector.inspect(httpReq);
      req.tracefield = result;

      const actionResponse = detector.resolveResponse(result);

      if (actionResponse.shouldIntercept) {
        res.status(actionResponse.status);
        for (const [key, val] of Object.entries(actionResponse.headers)) {
          res.setHeader(key, val);
        }
        res.send(actionResponse.body);
        return;
      }

      next();
    } catch (err) {
      // Fail-open principle to prevent security middleware errors from breaking app
      console.error('[tracefield/express] Middleware error:', err);
      next();
    }
  };
}

export const tracefield = tracefieldExpress;
export default tracefieldExpress;
