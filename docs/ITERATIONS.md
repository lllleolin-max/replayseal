# Implementation and review iterations

This log records observed findings and executed checks, not invented defects. Each substantive self-review correction will be a separate Git commit; exact before/after hashes are added after commits exist. Hosted CI is configured but local execution is the only result claimed here.

## Initial implementation

The initial version includes keyed recursive redaction, canonical structured signatures, strict ordered replay, declared causal edges, content-addressed evidence, standalone verification, CLI inspection/export/diff, an offline incident and executable mechanism ablation. Initial tests establish the baseline before dedicated adversarial self-review.

Initial commit: `895d446e708f57ad898e54d96e1fb090ebc68345`. Windows Python 3.14.3: `py -3 -m unittest discover -s tests -v` → 21 tests, OK. Offline incident → 2 recording calls, 0 replay live calls, event 2 argument mismatch caught. Ablation → all six explicit checks true.

## Round 1 — state-machine audit

Before: `895d446e708f57ad898e54d96e1fb090ebc68345`.

Observed with `py -3 -m unittest discover -s tests -p test_review_state.py -v`: **4 tests, 4 failures**. An unsupported tool result permitted sealing a shorter successful trace; nested calls reused sequence IDs and executed an inner callable; modifying a caller-owned rule list changed a frozen policy; invalid replay JSON raised without poisoning the session.

Correction: added capture completion/failure state, rejected nested/cross-thread recording before inner invocation, prevented sealing incomplete capture, snapshotted rule lists as tuples, and made invalid replay arguments terminal. Maintained explicit sets of completed events for dependency checks instead of repeatedly scanning the history.

After: `9f02e9add856f1288bbb5c0efbc2d566e8112ef4`. Verification: `py -3 -m unittest discover -s tests -v` → **25 tests, OK**; `py -3 examples/incident.py --output demo-output/round1` → 0 replay live calls and regression caught; `py -3 benchmarks/ablation.py` → all six checks true.

## Round 2 — privacy and identity-flow audit

Before: `9f02e9add856f1288bbb5c0efbc2d566e8112ef4`.

Observed with `py -3 -m unittest discover -s tests -p test_review_privacy.py -v`: **4 tests, 4 failures**. Unchanged text containing a pseudonym and redacted dictionary keys failed downstream matching; sequential overlapping regex substitutions left a sensitive suffix visible; a raw password in an exception message and a dynamic exception class name leaked to evidence.

Correction: preserve verified replay provenance for embedded text and keys; find/merge overlapping spans on original text; tokenize entire exception messages and restrict error class labels to a built-in allowlist. Bumped policy semantics version so prior/different rule behavior cannot silently compare. Ordinary token-shaped caller strings remain untrusted.

After: `6e60681b164d9a769e4083d43678da59037499f7`. Verification: `py -3 -m unittest discover -s tests -v` → **29 tests, OK**, including all four previously failing privacy probes.

## Round 3 — evidence and canonical contract audit

Before: `6e60681b164d9a769e4083d43678da59037499f7`.

Observed with `py -3 -m unittest discover -s tests -p test_review_evidence.py -v`: **4 tests, 4 failures**. Rehashed malformed error outcomes passed schema verification; signed-zero differences were reported equal by the differ despite distinct canonical signatures; public event inspection exposed mutable backing records and permitted redaction bypass; total evidence size had no aggregate budget.

Correction: validated safe error labels/opaque message schema, aligned scalar comparison with canonical bytes, made public event inspection independent snapshots, enforced a 64 MiB read budget in addition to file limits, rejected linked evidence directories, and rejected oversized capture arguments before invoking a tool. The private backing records remain within the trusted Python process boundary; this is not tamper resistance against executing malicious Python.

After: `c5693d4736d796a09347aba9d6d3f99e339058ba`. Verification: `py -3 -m unittest discover -s tests -v` → **33 tests, OK**; `py -3 examples/incident.py --output demo-output/round3` → 2 captured calls, 0 live calls during replay and cross-customer regression rejected; `py -3 benchmarks/ablation.py` → six checks true.

## Final handoff review — cumulative capture and CLI completeness

Before: `c5693d4736d796a09347aba9d6d3f99e339058ba`.

Observed with the first two probes in `test_review_final.py`: `py -3 -m unittest discover -s tests -p test_review_final.py -v` → **2 probes: 1 failure, 1 error**. A patched 1,100-byte aggregate cap allowed a second capture event until seal; the CLI lacked an executable replay workflow and rejected `replay` as an unknown command. The prior 33-test suite and six-check ablation were independently rerun successfully before modifying code.

Correction: track exact canonical event bytes and manifest-reference overhead incrementally and terminally reject overflowing capture; implement a data-only replay plan with JSON Pointer references to earlier successful results, explicit edges and explicit error expectations; preserve pseudonym provenance across reference resolution; return private summaries with exit codes 0/1/2. Update packaging to SPDX MIT metadata with its required setuptools minimum. Add tests for changed recipients, removed edges, dropped calls, invalid/forward references, bad keys, error expectations and trusted-root detection of completely rehashed rewrites.

After: `39b5a11d7bbb384dce01fc42413c24c08ea3b81e`. Verification on Windows Python 3.14.3: `py -3 -m venv .venv`, then `.venv/Scripts/python.exe -m pip install .` → non-editable wheel successfully built and installed with no runtime dependencies; `.venv/Scripts/python.exe -m unittest discover -s tests -v` → **39 tests, OK**. `.venv/Scripts/python.exe examples/incident.py --output demo-output/final` → **2 capture calls, 0 replay live calls**, event 2 wrong-customer mismatch rejected and configured synthetic sensitive literals absent. Set the published synthetic demo key in `REPLAYSEAL_KEY`, then `.venv/Scripts/python.exe -m replayseal replay demo-output/final/incident demo-output/final/incident.plan.json` → **2 events matched, 0 live calls, 0 recorded errors**. `.venv/Scripts/python.exe benchmarks/ablation.py` → **eight checks true**. `.venv/Scripts/python.exe benchmarks/measure.py --calls 500 --rounds 5` was rerun after the correction commit; median recording/sealing **3,542.101 ms**, verify **1,915.414 ms**, replay with verify **1,955.388 ms**, each evidence directory **224,656 bytes**. Raw timings and bounded interpretation are in `docs/BENCHMARKS.md` and `benchmarks/latest-results.json`.

The final evidence-only commit updates this log and measurement artifacts without changing executable code. Hosted GitHub CI has not yet run. Remaining boundaries: plans do not execute actual orchestration branches; SDK replay does. Memory/CPU isolation, rollback of live tool effects, universal secret detection and author authenticity remain outside scope. No production adoption or revenue has been established.

## Independent review correction — privacy composition

Before: `3afde4ff2bbe5bd2152dee77574006f54d125852`. The independent reviewer rejected this revision after finding a public-API privacy bypass; the earlier four corrections remain valid history but did not prevent this defect.

Observed before correction: `.venv/Scripts/python.exe ../reviews/replayseal_privacy_composition_probe.py` ran the installed old wheel and printed `configured_field_raw_prefix_persisted: True`, then raised `AssertionError` (exit 1). A legitimate same-policy/key Replay result contained both a pseudonym and readable `bare-sensitive-prefix`; placing it under the configured `password` field bypassed full-value protection. No private class/state was constructed or modified by the probe. The unchanged independent script is copied into `benchmarks/privacy_composition_probe.py` so the witness can run in the standalone repository.

The first eight targeted tests in `test_review_composition.py`, executed with the same old wheel, produced **5 failures, 1 error, 2 passes**: field/path/new-field/new-regex composition leaked the prefix, protected nested containers failed canonicalization, and the unreplayable original-full-value promotion gave only a generic difference. Existing complete-token identity and wrong-key rejection passed. Subsequent tests additionally cover a stricter path, regex spans crossing opaque tokens and successful original capture/replay with upstream full-value protection.

Correction: distinguish whole opaque tokens from partial text; apply full-field/path rules before accepting partial provenance; normalize nested verified strings with key checks for whole-container protection; retain complete same-key identity tokens; attach source policy identity and reapply different-policy regexes to readable text/keys while treating tokens as opaque. Target regex matches crossing a token hide the whole matched token region. Match lookup uses ordered token intervals rather than scanning every token for every match. On an unmatchable whole-value promotion, replay remains strict and raises terminal `ReplayMismatch` with a controlled, payload-free explanation. Policy semantics advances to v3 (library 0.1.1), preventing old replay fingerprints from silently inheriting new behavior.

Executed validation: `py -3 -m venv .venv-composition`, then `.venv-composition/Scripts/python.exe -m pip install --no-cache-dir .` → clean noneditable `replayseal-0.1.1` wheel installed; `.venv-composition/Scripts/python.exe -m unittest discover -s tests -v` → **50 tests, OK**. The original independent composition script (unchanged) now prints `configured_field_raw_prefix_persisted: False` and exits **0**; the independent broad probe script → **9 tests, OK**. Original incident SDK/CLI: **2 capture / 0 replay live calls**, wrong-customer regression rejected. New `examples/composition.py` SDK/CLI: **2 target capture / 0 replay live calls**, configured target literals absent, original source byte-for-byte unchanged. Eight mechanism ablation checks remain true.

The exact correction SHA and its measurement artifact are added in the following evidence-only commit. Remaining limits: hidden originals cannot be recovered from partial pseudonyms; configure upstream full-value fields/paths to support later whole-value matching, or expect explicit terminal replay failure. New target recordings whose input is already sanitized replay their exact protected signatures. The source evidence is never rewritten. Hosted CI and independent reacceptance of the new SHA remain pending.
