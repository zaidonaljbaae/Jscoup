"""Local function throughput. No HTTP or distributed-capacity claims."""
import json, platform, time
from jscoup import JSCoup, MemoryStorage

def run(mode, count=10000):
    store = MemoryStorage()
    options = dict(storage=store, dashboard_local_dev=True, capture_success=True)
    if mode == 'background': options.update(async_storage=True, event_queue_size=1024)
    if mode == 'sample_1_percent': options.update(async_storage=True, sample_rate=.01)
    x = JSCoup(**options)
    def work(): return 1
    fn = work if mode == 'bare' else x.watch()(work)
    start = time.perf_counter()
    for _ in range(count): assert fn() == 1
    ingress = time.perf_counter() - start
    drained = x.flush(30)
    total = time.perf_counter() - start
    stats = x.metrics()
    x.close(30)
    return dict(mode=mode,calls=count,calls_per_second=round(count/ingress),elapsed_with_flush=round(total,4),drained=drained,metrics=stats)

if __name__ == '__main__':
    print(json.dumps({'python':platform.python_version(),'platform':platform.platform(), 'results':[run(m) for m in ['bare','synchronous','background','sample_1_percent']]},indent=2))
