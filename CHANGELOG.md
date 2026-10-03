# Changelog

## 0.1.2

- Public Replay results now support `copy.copy()` and `copy.deepcopy()` while
  retaining key/source-policy provenance. Complete tokens, partially redacted
  text and nested dictionary/list/key compositions are supported; copied string
  objects have separate provenance attributes and deepcopy preserves aliases.
- The composition example copies its working contexts and demonstrates a
  stricter target recording with zero live boundary calls during replay.
- Added adversarial copy/composition regressions. Foreign keys, ordinary
  token-looking strings and unreconstructable original full-value HMACs retain
  their existing fail-closed behavior.

Policy semantics remains v3. Existing v0.1.1 evidence fingerprints, canonical
signatures and roots are unchanged and remain replay-compatible. No plaintext
recovery, broader privacy detection, remote effects or performance claim was
added. Customer adoption and production savings remain unverified.

## 0.1.1

Repaired whole-field/path and stricter-policy composition of partially redacted
Replay strings. Policy semantics advanced to v3, with explicit terminal failure
when a replay cannot reconstruct an original full-value HMAC.
