import json, os, platform, tempfile, time
from jscoup import JSCoup, MemoryStorage
root = tempfile.mkdtemp(prefix='jscoup-bench-')
bl = JSCoup.high_volume('benchmark', storage=MemoryStorage(), dashboard_enabled=False, call_log_db_path=os.path.join(root,'calls.db'))
count = 10000
start = time.perf_counter()
for _ in range(count):
    ctx = bl.begin(kind='http', name='GET /synthetic', method='GET', path='/synthetic')
    ctx.status_code = 200
    bl.end(ctx)
producer = time.perf_counter() - start
flushed = bl.flush(30)
end_to_end = time.perf_counter() - start
result = dict(python=platform.python_version(), calls=count, producer_seconds=producer, producer_calls_per_second=count/producer, total_seconds=end_to_end, flushed=flushed, stored_rows=bl.call_log.count(), metrics=bl.metrics(), scope='Single-process synthetic metadata capture; not HTTP throughput or a capacity SLA')
bl.close()
print(json.dumps(result, indent=2))
