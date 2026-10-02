# Security and trust boundaries

Please do not put actual credentials or customer evidence in public issues. Report a sensitive defect via the repository's private security-reporting facility if enabled; otherwise open a minimal issue asking for a private channel, without exploit payloads containing personal data. This young project has no promised response SLA or external security audit.

## What is enforced

- Configured redaction occurs in memory before the library writes evidence or temporary evidence files. The private key and literal policy expressions are not exported.
- HMAC-SHA-256 separates identical and distinct sensitive values with a private 32+ byte key. Reusing a key intentionally permits linking the same value across traces.
- Replay verifies the evidence, then requires the next recorded tool, canonical arguments and causal edges. The replay code never invokes the supplied tool callable.
- Export includes only referenced, verified objects; independent verification needs Python 3.11+, not this package.

## What is trusted / not proved

Caller orchestration, Python process memory, operating system, tool names, tool registration, policy rules and key storage are trusted. This is not an adversarial-code sandbox. Code outside wrapped boundaries can execute network requests or mutate files. Recording executes tools normally and cannot undo their effects. Signals, crashes, user logging and swap files are outside pre-persistence redaction guarantees.

Defaults detect selected forms, not all secrets/PII. Values in unconfigured fields and unknown formats may remain. File paths and tool names must be static non-sensitive application metadata. Pseudonyms leak equality, frequency, structure for fields that are not fully redacted, and chronology. Key compromise permits guessing low-entropy identifiers. A pseudonym is not anonymization. Losing a key prevents faithful matching of raw arguments; there is no secret-recovery feature.

An attacker able to replace both objects and manifest can compute new content hashes. Supply an externally trusted `expected_root` when adversarial tampering matters. A verified bundle establishes internal consistency and agreement with that root; it does not authenticate the recorder, demonstrate factual events or certify that all secrets were removed. The bundled verifier itself should come from a trusted release or be inspected before execution.

The format is plain JSON with type-sensitive canonical signatures. Only synchronous, sequential, non-nested calls with ordinary JSON values are within the intended first-release integration scope. Strict order intentionally rejects benign scheduling changes. Dependencies are supplied by the caller; the library validates them but does not infer true causation.

Redacted values are opaque. Equality and unchanged pass-through are meaningful; transformations, lengths, arithmetic and new computations requiring original secrets are not reproduced. Keep those computations inside a boundary or construct reviewed synthetic fixtures. Recorded exceptions are re-raised as a generic wrapper to avoid loading arbitrary code from a trace.

File-level byte and JSON-depth limits defend basic accidental/adversarial oversized inputs; the process is not a memory/CPU isolation boundary. Regex configuration is trusted and can be computationally expensive. Do not open evidence in a directory concurrently modified by an attacker.

CLI replay plans are JSON data and cannot load recorded tool code. Its key comes from an environment variable; never put it in command arguments, a plan or a shared policy file. Plans may still contain caller-supplied raw arguments and are not automatically sanitized or exported. The CLI intentionally prints only a match summary or controlled mismatch reason. Resolved templates, decoded JSON and recorder results can require more memory than their serialized sizes; aggregate caps do not provide process isolation. Failed result capture cannot roll back a live tool invocation.
