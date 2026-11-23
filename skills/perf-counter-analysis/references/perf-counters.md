# Performance counters in the dump

## Where they live

Every object (`CObject`) whose class defines performance counters owns a `CObjectPerformance` (`performance_`). It holds
one item per counter (code = `CModelPerformance::CODEENUM`, name `MODEL_PERF_<NAME>`), and per item a buffer for every
timebase and aggregate:

| Timebase | Bucket | Buffer keeps | Typical number of buckets |
|---|---|---|---|
| `second` | 1 s | the last minute | ~60 |
| `minute` | 1 min | the last hour | ~60 |
| `hour` | 1 h | the last day | up to 24 (fewer if the process ran shorter) |
| `day` | 1 day | the last 30 days | up to 30 |

Bucket starts are multiples of the period in UTC (`now - now % period`), so buckets of different objects and counters
line up. Objects are found by path in `inmation::model::_maps` (canonical paths, compared case-insensitively for ASCII).

## Aggregates per bucket

Most counters get one sample per second (a timer calls `Performance()->Set(code, value)`); some count events
(`Increment`) and are turned into a per-second delta once per second.

| Aggregate | Meaning | Use it for |
|---|---|---|
| `avg` | sum / num | the level in that bucket (default in charts and correlation) |
| `min`, `max` | smallest / largest sample in the bucket | short peaks that the average hides (CPU 25% avg, 88% max) |
| `num` | number of samples | gaps: fewer than 60 per minute bucket means samples were missing (timer stalled, process busy) |
| `sum` | total of the samples | rates: events per bucket; meaningless for levels such as memory |

In `second` buckets min = max = avg (one sample). The **last bucket of each timebase is still filling** at dump time
(fewer samples; drawn as a hollow marker, left out of the statistics). Its `num` shows how far into the bucket the dump
was taken.

## Reading the summary and charts

- *Mean of avg / Min / Max* use complete buckets only. *Max at* is the bucket with the highest sample.
- *Trend* compares the first and the last third of the bucket averages: `rising (+35%)`, `falling (-20%)`, `flat`
  (change < 10%), `n/a` (< 6 buckets).
- Counters named `*_TOTAL` are cumulative: they only rise; their changes per bucket are the rate.
- A counter reported as `constant 0` is not active in this process (feature not used); not an error.
- `num` lower than expected in complete buckets (e.g. 60, 60, 41, 12 per minute before the dump) can mean that the
  sampling timer did not run (process busy or blocked) - relevant for hang dumps - or that the process started inside
  the bucket. State it as a possibility.
- Units are not in the dump. Use the name only when it is unambiguous (`...PERCENTAGE`); otherwise say "value" and
  that the unit is not known from the dump.

## Limits

- Needs a dump with full memory (the counters are on the heap) and the verified PDB of the build.
- Windows dumps of inmation.exe only (Linux cores not yet).
- The dump is one moment: the buffers cover at most the last minute / hour / day / 30 days before it.
