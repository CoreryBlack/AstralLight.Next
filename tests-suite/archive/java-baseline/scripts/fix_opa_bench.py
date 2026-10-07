import sys

filepath = sys.argv[1]
with open(filepath, 'r') as f:
    content = f.read()

old = '''        try {
            opaAdapter.initialize(dataset);
            result.singleThreadSnapshot = opaAdapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkOpaConcurrent(dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }'''

new = '''        opaAdapter.initialize(dataset);
        result.singleThreadSnapshot = opaAdapter.benchmarkEval(dataset, iterations);
        if (concurrency > 1) {
            try {
                result.concurrentSnapshot = benchmarkOpaConcurrent(dataset, iterations, concurrency);
            } catch (Exception e) {
                log.warn("{} concurrent benchmark failed: {}", label, e.getMessage());
            }
        }'''

assert old in content, 'OLD text benchmarkOpa not found!'
content = content.replace(old, new, 1)

old2 = '''        try {
            opaCachedAdapter.initialize(dataset);
            result.singleThreadSnapshot = opaCachedAdapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkOpaCachedConcurrent(dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }'''

new2 = '''        opaCachedAdapter.initialize(dataset);
        result.singleThreadSnapshot = opaCachedAdapter.benchmarkEval(dataset, iterations);
        if (concurrency > 1) {
            try {
                result.concurrentSnapshot = benchmarkOpaCachedConcurrent(dataset, iterations, concurrency);
            } catch (Exception e) {
                log.warn("{} concurrent benchmark failed: {}", label, e.getMessage());
            }
        }'''

assert old2 in content, 'OLD text benchmarkOpaNoCache not found!'
content = content.replace(old2, new2, 1)

with open(filepath, 'w') as f:
    f.write(content)

print('PATCH_OK')
