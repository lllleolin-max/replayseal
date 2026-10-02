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

After commit is recorded once it exists. Verification: `py -3 -m unittest discover -s tests -v` → **33 tests, OK**; `py -3 examples/incident.py --output demo-output/round3` → 2 captured calls, 0 live calls during replay and cross-customer regression rejected; `py -3 benchmarks/ablation.py` → six checks true.
