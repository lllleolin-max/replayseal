# Format and API contract

`Recorder(path, policy)` buffers only sanitized event snapshots, then seals a fresh directory. Context exit seals the captured run. `call(tool, arguments, invoke, depends_on=())` invokes `invoke(arguments)` once, captures its JSON result or exception and returns the original result during recording. `last_id` is the prior completed event identifier. Decorators bind Python function signatures and defaults; they do not infer dependency edges.

`Replay(path, policy, expected_root=None)` validates the whole directory before returning recorded values. The policy and private key must match. The same `call` shape is accepted but `invoke` is unused. Replay outputs include private Python string subclasses for pseudonym provenance; ordinary user strings resembling tokens are re-tokenized instead of being trusted. `finish()` enforces complete consumption. Context exit calls it after a normally completed workflow.

Each event contains exactly `id`, `tool`, `arguments`, `signature`, `depends_on`, `outcome`. IDs are `e000001` onwards. Dependencies are sorted unique earlier event IDs. Call signatures hash canonical `{tool, arguments}` after redaction. Outcomes contain either `{kind: return, value}` or `{kind: error, type, message}`.

Objects are stored at `objects/<sha256>.json`. `manifest.json` has exactly `format`, `policy_id`, `key_id`, `events` (ordered object digests), and `root`. The root hashes the other manifest fields. Policy ID hashes the redaction configuration; key ID is a domain-separated HMAC, never the key itself.

Canonicalization uses sorted-key compact UTF-8 JSON. Dictionary insertion order is irrelevant; array order, string content, booleans, integers and floating-point numbers retain distinct serialization. No NaN/infinity, bytes, tuples, datetimes, arbitrary classes, duplicate JSON keys or more than 100 nesting levels. This is a Python format contract, not an implementation of RFC 8785. Unicode strings are not normalized; callers must choose their normalization deliberately. Files are capped at 16 MiB and manifests at 100,000 events.

Verification checks structural constraints even after a caller recomputes hashes; dependency cycles/forward references are invalid. Content addressing binds the serialized graph, not real-world causal truth. `compare` reports only first divergence; different policies or keys are incomparable. Export uses fixed ZIP timestamps and referenced objects, omitting unrelated files.
