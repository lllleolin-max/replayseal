# Contributing

Use Python 3.11 or newer in an isolated environment. Install with `python -m pip install -e .`, then run `python -m unittest discover -s tests -v`, `python examples/incident.py --output demo-output-new` and `python benchmarks/ablation.py`.

Changes to the format, canonicalization, policy identities or pseudonym representation need compatibility discussion and new adversarial fixtures. Tests should demonstrate a real guarantee, not just count functions. Use synthetic data and public test keys. Windows and Ubuntu CI cover the supported Python versions; local results are not a claim that hosted CI has run.

Keep the synchronous explicit-boundary scope small. Prefer interoperable JSON and standard-library mechanisms. Proposals for automatic instrumentation, async scheduling and live cut-point execution should document their new trust and concurrency models before implementation.
