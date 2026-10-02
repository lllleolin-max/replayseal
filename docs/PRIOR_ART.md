# Prior art and positioning

Primary documentation checked 2026-10-03. The comparison describes documented scope, not a claim that another tool cannot be extended to do this.

| Source | Existing capability | replayseal's chosen boundary |
|---|---|---|
| [VCR.py configuration](https://vcrpy.readthedocs.io/en/latest/configuration.html), [filtering](https://vcrpy.readthedocs.io/en/latest/advanced.html) | HTTP cassette recording/playback, configurable request matching and request/response filtering | Explicit JSON agent tool boundaries, identity relationships under keyed redaction, ordered calls and declared causal edges |
| [LangSmith masking](https://docs.langchain.com/langsmith/mask-inputs-outputs), [evaluation API](https://reference.langchain.com/python/langsmith/client/Client/evaluate) | Trace masking/hiding, configurable anonymizers, evaluation of application runs | Small local regression fixtures with no server, plus a standalone evidence verifier |
| [OpenTelemetry overview](https://opentelemetry.io/docs/), [sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/) | Vendor-neutral telemetry and guidance/processors for minimizing sensitive information | Executable strict replay contract rather than observability infrastructure |
| [Chronicle, Chawla & Koul, 2026](https://arxiv.org/abs/2609.20625) | Immutable agent boundary envelopes, full/cut-point replay and a six-incident regression study | No live cut points; emphasizes configurable pre-persistence keyed identities, explicit dependencies and independent portable verification |

No competitor performance numbers are compared: we have not run their benchmarks or attempted feature-equivalent adapters. In particular, replay, immutable records, offline testing and filtering are prior art. Hashes and HMAC are standard primitives. The contribution here is a specific reproducible interaction among these pieces, not a new cryptographic algorithm.

`python benchmarks/ablation.py` compares minimal mechanism baselines: raw JSON recording, constant replacement and keyed replacement. It then removes one explicit causal edge and changes one recipient in the real replay engine. Constant replacement collapses the two recipients; keyed replacement keeps them distinct without storing either literal. Ordered signature matching alone cannot detect a removed declared edge when names/arguments/order stay the same. These are falsifiable properties of this implementation, not claims about VCR.py, LangSmith or Chronicle defaults.

The useful target is an agent platform or support engineering team reproducing a customer incident across a privacy boundary. Hosted evaluation, token usage accounting, model quality scores and distributed trace search remain better served by observability/evaluation platforms.
