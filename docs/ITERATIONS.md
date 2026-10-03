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

After: `ee9ab608810aef11c48a69ddff93d419977a3ba5`. The unchanged copied reviewer probe and original script both have SHA-256 `b25930d57f846f5beff7ce19c6d1b9a560cd71278f0c2ac48acc7d1f36f954c6`. `.venv-composition/Scripts/python.exe benchmarks/measure.py --calls 500 --rounds 5` was run at this code commit: **5 rounds**, median recording/sealing **5,331.658 ms**, verification **2,692.287 ms**, replay with verification **3,050.968 ms**, **224,656 bytes** of evidence per round. Every raw timing is in `benchmarks/composition-results.json`; these observations do not establish speed improvements or isolate overhead from other machine activity. The following evidence-only commit records these results without executable code changes.

Remaining limits: hidden originals cannot be recovered from partial pseudonyms; configure upstream full-value fields/paths to support later whole-value matching, or expect explicit terminal replay failure. New target recordings whose input is already sanitized replay their exact protected signatures. The source evidence is never rewritten. Hosted CI and independent reacceptance of the new SHA remain pending.

## v0.1.2 — provenance-preserving copy review

These three additional self-review rounds were run on Windows/Python 3.14.3 on
2026-10-03. They preserve the old failed review, correction records, releases and
v3 evidence. One new product defect was corrected; the two later review rounds
found no additional product defect. Added tests, example changes, versioning and
documentation are not represented as three separate code corrections.

### Round 1 — public output copying

Before: `28b53abc3e09ad60d833c50538e8fe3ef584b6dd` (v0.1.1). Rebuilt with
`git -c core.autocrlf=false archive`, an ordinary wheel and a fresh virtual
environment. An isolated interpreter confirmed raw Git blob, LF archive, wheel
and installed bytes identical for all seven package modules. The original
installed suite passed **50 tests** (2.460s).

Six public-API copy regressions were then run against that exact old wheel:
**FAILED (errors=10)**, 0.272s; subtests account for the extra errors. After a
fully consumed Replay context, shallow/deep copying complete tokens, partial
readable text and dictionary keys raised `_Pseudonym.__new__` TypeError. Deep
copying nested result containers stopped for the same reason. The ordinary
token-looking-string boundary already passed and was not weakened.

Correction: `55dfc7f1b5221609dea6aeb03a55eccd6dc8ca51`. Explicit copy protocols
reconstruct only an existing Replay-issued value and its key/policy provenance
in a separate string object. Deepcopy records the new object in its memo,
preserving repeated-reference relationships. A new ordinary installed wheel ran
the same copy tests successfully and the full **56 tests passed** (2.216s).
Tests also check detached nested containers, same-key target recording/replay,
foreign-key rejection before invocation and terminal original-full-value
promotion failure. Policy semantics, canonical signatures and evidence format
are unchanged.

### Round 2 — copied composition privacy matrix

Reviewed the same correction, then added four matrix tests at
`d4a7a7897ce5a33c94c28225c8eb7200666c64bc`. They passed against the round-1 ordinary
wheel: **4 tests, OK** (0.651s). Ten shallow/deep field/path/container/regex cases
produce exactly the same target evidence roots as direct pass-through. Further
cases exercise opaque-token stability under token-matching stricter patterns,
foreign-key dictionary keys inside protected containers, and upstream-whole
protection through SDK orchestration and result-reference plans.

The updated composition example actually copies its nested working contexts and
identity strings. It reports **2 capture calls / 0 replay live calls**, detached
context, retained provenance, absent configured literals and unchanged source
evidence. Its target root remains the v0.1.1 value
`ec62ffc438b24e7bb1159307a8cf9ac0f30288245410c48cb1ddc80aa16ce3f5`.
No additional product correction was needed. Shallow copies retain nested
container sharing according to normal Python semantics; deep copies detach it.

### Round 3 — installed SDK, CLI and old-v3 compatibility

Fetched and normally merged the parallel public README update
`fcb35d8f72ab7839cdc05b2cae90aaf2d7be8a17` before versioning, preserving its new
cross-platform installation and usage explanations. At candidate
`18e194b5e0fd2c1cbad7886a82bae6d02363d29c` (v0.1.2), a new LF Git archive,
ordinary wheel, fresh environment and isolated import again matched all seven
raw Git module bytes. **60 installed tests passed** (2.995s), including all
original 50 tests and ten new copy/composition tests.

Synthetic traces captured with the exact v0.1.1 baseline wheel were replayed
directly under v0.1.2, with copies in the actual orchestration. Existing key and
policy fingerprints, canonical event objects and evidence roots stayed equal;
every original file hash was unchanged. Upstream whole protection succeeds;
partial-to-original-whole promotion remains terminal with zero live callbacks.
One initial compatibility fixture moved a protected `customer_id` into an
unprotected `identity` field during original capture. Its downstream contract
needed hidden original plaintext and correctly failed. That trace and failed
harness result were retained; a separate fixture kept the downstream field
protected. No original failure was overwritten or made to pass by relaxing
matching.

The actual `sysconfig` console executable replayed the protected old trace under
native Windows encoding and `PYTHONUTF8=0/1`: each **exit 0, 2 events, 0 live
calls**. Both incident and copied-composition examples passed; their published
roots remain unchanged. The original privacy witness exited 0. Actual CLI bundle
export and the extracted standalone verifier exited 0 against the old trusted
root. No additional product defect was found in this round.

The final documentation commit records these observations without changing the
tested package code. Release verification must associate its final Git archive
with the ordinary wheel and installed bytes. This builder does not assert new
independent scores, hosted CI, customers, revenue or performance gains. JSON
serialization and string transformations still lose runtime provenance; copies
cannot recover hidden originals, expand configured privacy coverage, bypass a
foreign key or invoke a live replay callback.
