# Reproducible measurements and commercial hypothesis

Run `python benchmarks/measure.py --calls 500 --rounds 5`. The script reports every timing sample, medians, runtime/platform and evidence size. It measures a synthetic CRM-shaped JSON tool; no model/network is called. Recording includes redaction, hashing, writes and verification; replay includes verification. It is not a throughput promise or a competitor benchmark.

Measured 2026-10-03 at code commit `39b5a11d7bbb384dce01fc42413c24c08ea3b81e`, after a non-editable wheel install into a fresh virtual environment. Python 3.14.3, Windows 11 build 26200, 500 calls per round, 5 rounds. [Raw samples and provenance](../benchmarks/latest-results.json) are committed; no timing samples were discarded.

| Operation | Median per 500-call round |
|---|---:|
| Record, seal and verify | 3,542.101 ms |
| Verify existing evidence | 1,915.414 ms |
| Replay, including initial verify | 1,955.388 ms |

Each round produced 224,656 bytes of evidence including its manifest. These filesystem-heavy Windows results are a local observation, not evidence of better latency than Chronicle, Keploy or another implementation. Storage, antivirus, caches and concurrent machine activity affect timing. The measured tool callable only returns small synthetic JSON; no external-call latency is included.

`python benchmarks/ablation.py` is the separate executable privacy/identity/causality contrast, not a timing comparison. All eight checks were true: the constant-identity signature baseline accepted the wrong recipient, the signature-only baseline accepted the removed edge, and the real replay engine rejected each corresponding regression.

## Privacy-composition correction measurement

After the independent privacy repair, the same command was executed at code commit `ee9ab608810aef11c48a69ddff93d419977a3ba5` using a fresh noneditable 0.1.1 wheel on the same Python/OS, 500 calls × 5 rounds. [All raw samples](../benchmarks/composition-results.json) are retained separately from the historical results above.

| Operation | Median per 500-call round |
|---|---:|
| Record, seal and verify | 5,331.658 ms |
| Verify existing evidence | 2,692.287 ms |
| Replay, including initial verify | 3,050.968 ms |

Evidence size remained 224,656 bytes in each round. The substantial sample variation, including verification timings where the verifier code did not change, means these separate runs cannot isolate the repair's incremental overhead. No faster-than-before or incumbent-performance claim is made. The ordinary CRM timing workload does not benchmark every stricter-policy composition; `python benchmarks/privacy_composition_probe.py` and `python examples/composition.py` are separate correctness workflows.

## Buyer and workflow

Hypothesis: an agent platform or customer-support engineering team needs to hand a reproducer from incident triage to a developer/CI runner without copying customer identities or invoking production write tools. Today, teams can already combine VCR-style stubs, trace masking and custom test code; this package reduces the integration surface for one narrow workflow and makes first divergence and independent evidence verification explicit.

Example economic model, **assumptions, not measured savings**: 30 incident fixtures × 12 CI runs/day × 2 model/tool calls per fixture = 720 boundary calls/day replaced by local replay. If each avoided external call costs $0.01 and 300 ms, the nominal avoided variable expense is $7.20/day and sequential waiting time is 216 seconds/day. Parallelism, caches, failed recordings, maintainer time and calls outside boundaries change those numbers. No claim is made that these assumptions match any customer.

Actual observed mechanism: the demo increments a synthetic live-call counter for two recording calls and adds zero during both successful and rejected replay. The wrong-customer mutation fails before the would-be write callable. Identity-aware pseudonyms retain that decision where the constant-replacement ablation cannot. That is a pilot-worthy mechanism, not product-market-fit proof.

A sustainable first scope is a small MIT SDK, deterministic fixture format and paid integration/support only if users later request it. Current customer count, revenue and production adoption are unvalidated; no revenue or willingness-to-pay claim is made. Key provisioning, policy review and narrow tool integration are real adoption costs. Data that must be transformed outside a boundary may require synthetic fixtures and cannot be faithfully replayed by opaque pseudonyms.
