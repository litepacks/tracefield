export * from './types.js';
export * from './rules/index.js';
export * from './normalizer/index.js';
export * from './matcher/index.js';
export * from './session/index.js';
export * from './decoy/index.js';
export * from './scoring/index.js';
export * from './events/index.js';
export * from './actions/index.js';
export * from './explain/index.js';
export * from './detector.js';

import { createDetector, inspect } from './detector.js';
import type { DetectorOptions, HttpRequest, InspectionResult } from './types.js';

export const tracefield = Object.assign(
  (options?: DetectorOptions) => createDetector(options),
  {
    inspect: (req: HttpRequest, opts?: DetectorOptions): Promise<InspectionResult> => inspect(req, opts),
    createDetector: (opts?: DetectorOptions) => createDetector(opts)
  }
);

export default tracefield;
