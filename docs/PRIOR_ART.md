# Prior art and positioning

Primary documentation checked 2026-10-03. The comparison describes documented scope, not a claim that another tool cannot be extended to do this.

| Source | Existing capability | replayseal's chosen boundary |
|---|---|---|
| [Keploy introduction](https://keploy.io/docs/keploy-explained/introduction/) | Captures application interactions to create API tests and mocks and replays them | Explicit Python JSON boundaries with caller-managed keyed identity policy; no automatic traffic instrumentation |
| [VCR.py configuration](https://vcrpy.readthedocs.io/en/latest/configuration.html), [filtering](https://vcrpy.readthedocs.io/en/latest/advanced.html) | HTTP cassette recording/playback, configurable request matching and request/response filtering | Explicit JSON agent tool boundaries, identity relationships under keyed redaction, ordered calls and declared causal edges |
| [LangSmith masking](https://docs.langchain.com/langsmith/mask-inputs-outputs), [evaluation API](https://reference.langchain.com/python/langsmith/client/Client/evaluate) | Trace masking/hiding, configurable anonymizers, evaluation of application runs | Small local regression fixtures with no server, plus a standalone evidence verifier |
| [OpenTelemetry overview](https://opentelemetry.io/docs/), [sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/) | Vendor-neutral telemetry and guidance/processors for minimizing sensitive information | Executable strict replay contract rather than observability infrastructure |
| [Chronicle, Chawla & Koul, 2026](https://arxiv.org/abs/2609.20625) | Immutable agent boundary envelopes, full/cut-point replay and a six-incident regression study | No live cut points; emphasizes configurable pre-persistence keyed identities, explicit dependencies and independent portable verification |

No competitor performance numbers are compared: we have not run their benchmarks or attempted feature-equivalent adapters. In particular, replay, immutable records, offline testing and filtering are prior art. Hashes and HMAC are standard primitives. The contribution here is a specific reproducible interaction among these pieces, not a new cryptographic algorithm.

`python benchmarks/ablation.py` compares minimal mechanism baselines: raw JSON recording, constant replacement and keyed replacement. A signature-only stub matcher with constant identity replacement accepts the wrong recipient, while the keyed replay engine rejects it. A signature-only matcher accepts an otherwise identical call after an edge is removed; the real engine rejects it. The script executes all eight explicit checks. These baselines intentionally isolate each mechanism and do not model complete products; the results are falsifiable properties of this implementation, not claims about Keploy, VCR.py, LangSmith or Chronicle defaults.

The useful target is an agent platform or support engineering team reproducing a customer incident across a privacy boundary. Hosted evaluation, token usage accounting, model quality scores and distributed trace search remain better served by observability/evaluation platforms.
