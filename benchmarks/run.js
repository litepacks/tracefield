import { createDetector } from '../dist/index.js';

function percentile(sortedArr, p) {
  if (sortedArr.length === 0) return 0;
  const index = Math.ceil((p / 100) * sortedArr.length) - 1;
  return sortedArr[Math.max(0, Math.min(index, sortedArr.length - 1))];
}

async function runBenchmark(name, detector, request, iterations = 20000) {
  // Warmup
  for (let i = 0; i < 500; i++) {
    await detector.inspect(request);
  }

  const times = [];
  const startTotal = performance.now();

  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    await detector.inspect(request);
    const t1 = performance.now();
    times.push((t1 - t0) * 1000); // microseconds
  }

  const endTotal = performance.now();
  const totalMs = endTotal - startTotal;
  const opsPerSec = Math.round((iterations / totalMs) * 1000);

  times.sort((a, b) => a - b);
  const avgUs = (times.reduce((sum, v) => sum + v, 0) / times.length).toFixed(2);
  const p50Us = percentile(times, 50).toFixed(2);
  const p95Us = percentile(times, 95).toFixed(2);
  const p99Us = percentile(times, 99).toFixed(2);

  console.log(`| ${name.padEnd(32, ' ')} | ${String(opsPerSec).padStart(11, ' ')} ops/s | ${avgUs.padStart(8, ' ')} µs | ${p50Us.padStart(8, ' ')} µs | ${p95Us.padStart(8, ' ')} µs | ${p99Us.padStart(8, ' ')} µs |`);
}

async function main() {
  console.log('===================================================================================================');
  console.log('                                    tracefield Performance Benchmark                                    ');
  console.log('===================================================================================================');
  console.log(`Node.js Version: ${process.version}`);
  console.log(`Architecture:    ${process.arch}`);
  console.log(`Platform:        ${process.platform}`);
  console.log('---------------------------------------------------------------------------------------------------');
  console.log('| Scenario                         | Throughput     | Avg Lat  | p50      | p95      | p99      |');
  console.log('|----------------------------------|----------------|----------|----------|----------|----------|');

  const detector = createDetector({ mode: 'observe' });

  // 1. Normal safe request
  await runBenchmark('1. Normal Safe Request (/api/v1/item)', detector, {
    path: '/api/v1/items/49102',
    method: 'GET',
    ip: '198.51.100.1'
  });

  // 2. Exact malicious match
  await runBenchmark('2. Exact Malicious (/.env.prod)', detector, {
    path: '/.env.production',
    method: 'GET',
    ip: '198.51.100.2'
  });

  // 3. Prefix probe match
  await runBenchmark('3. Prefix Probe (/wp-admin/...)', detector, {
    path: '/wp-admin/includes/plugins.php',
    method: 'GET',
    ip: '198.51.100.3'
  });

  // 4. Suffix probe match
  await runBenchmark('4. Suffix Probe (/backup.sql.gz)', detector, {
    path: '/backup_prod_2026.sql.gz',
    method: 'GET',
    ip: '198.51.100.4'
  });

  // 5. Complex double-encoded traversal
  await runBenchmark('5. Double-encoded Traversal', detector, {
    path: '/%252e%252e/%252e%252e/etc/passwd',
    method: 'GET',
    ip: '198.51.100.5'
  });

  // 6. Active scanner session
  const scannerDetector = createDetector({ tracking: { enabled: true } });
  await runBenchmark('6. Active Scanner Session (Tracked)', scannerDetector, {
    path: '/.git/config',
    method: 'GET',
    ip: '198.51.100.6',
    headers: { 'user-agent': 'masscan/1.3' }
  });

  const mem = process.memoryUsage();
  console.log('---------------------------------------------------------------------------------------------------');
  console.log(`Heap Used: ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB | RSS: ${(mem.rss / 1024 / 1024).toFixed(2)} MB`);
  console.log('===================================================================================================\n');
}

main().catch(console.error);
