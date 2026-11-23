# Interpreting counter correlations

`Measure-PerfCorrelation.ps1` compares every selected pair per timebase on the complete buckets with the same UTC start
(`avg` per bucket unless `-Aggregate` says otherwise) and gives a deterministic pre-verdict. You explain it; you do not
change it. A correlation never proves that one counter causes the other.

## Measures

| Measure | What it says |
|---|---|
| `r` | Pearson correlation of the bucket values (-1..1). |
| `changes r` | Correlation of the bucket-to-bucket changes. High only if the counters rise and fall together from bucket to bucket - not if both merely drift up over the hour. |
| `rank r` | Spearman; robust to single extreme buckets. `r` high but `rank r` low = a few peaks carry the correlation. |
| `lag` | Shift (in buckets) of the changes with the best correlation; `+2` = B follows A two buckets later. |
| `n`, `p` | Common buckets and two-sided p-value of `r`. |
| changes | Buckets in which both counters change; with fewer than 5, `changes r` and lags are not used. |

## Pre-verdicts

| Pre-verdict | Rule | How to explain it |
|---|---|---|
| `strong` | \|r\| >= 0.8, p < 0.01, \|changes r\| >= 0.5, \|rank r\| >= 0.6, enough changes | The two move together bucket by bucket. Likely one drives the other or both share a cause. Name the plausible mechanism and the direction (`together` / `opposite`). Confidence medium-high, but never "proven cause". |
| `lagged` | changes correlate best shifted (\|r\| >= 0.6, p < 0.01, clearly better than unshifted) | B reacts to A after `lag` buckets (or A to B for negative lags): typical for queues and buffers (ingress first, backlog / egress later). |
| `moderate` | changes r significant (p < 0.01) and either \|r\| >= 0.5 with \|changes r\| >= 0.3, or \|changes r\| >= 0.5 alone | A real but partial link: peaks often coincide, other factors matter too. Confidence medium-low. |
| `inconsistent` | \|r\| >= 0.5 with opposite signs in different timebases | No stable relation; different effects at different time scales. Say so; do not pick a side. |
| `trend-only` | \|r\| >= 0.5 and \|rank r\| >= 0.5, but the changes do not correlate or are too few | Both drift or step in the same period (process warm-up, a load change, cumulative counters). Weak evidence of a link; usually a common time effect. |
| `same-signal` | \|r\| and \|changes r\| >= 0.97 in every timebase | One counter is derived from the other or both come from the same value (e.g. a value and its percentage, the same rate seen in two places). Not a finding; use one of them. |
| `none` | otherwise | No robust relation in these buckets. With hinted counters this is the answer ("CPU and X are not correlated in the last hour"). A high `r` with a low `rank r` means a few extreme buckets carry it: look at the pair chart and name those buckets instead of a relation. |

## Checklist for the answer

1. For each top pair: pre-verdict, direction, the evidence line (timebase, r, changes r, n) - facts.
2. Names that describe the same quantity (a value and its percentage, a rate and its total, an average and an
   accumulated runtime of the same thing) are probably derived from each other: say that the relation is likely by
   construction, with low confidence, instead of a behavioral explanation.
3. Common causes: both counters may follow overall load (script activity, number of clients, time of day). Prefer
   "both rise with X" over "A causes B" unless a lag shows the direction.
4. `*` scans compare thousands of pairs: some reach `moderate` by chance. Trust pairs that hold in more than one
   timebase, have a plausible mechanism, or match an anomaly (same spike time). Say that the scan is exploratory.
5. Anomalies (`PERF_ANOMALY=`): a spike or step at the same time in two counters supports a link; a step right before
   the dump time is relevant for hang / slow-down questions.
6. End with what would confirm the hypothesis: another dump later, counters of another object, logs around the spike
   time.
