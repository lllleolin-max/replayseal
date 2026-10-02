# replayseal

**Reproduce an agent tool incident without sharing its sensitive identifiers or calling the tools again.**

An offline Python SDK and CLI for teams turning customer-specific agent failures into CI regression fixtures. Record JSON tool boundaries, replace configured secrets and identifiers with stable keyed pseudonyms **before writing any evidence**, then replay a strict ordered contract with explicit causal dependencies. Export a content-addressed evidence bundle a colleague can verify using Python alone.

Python 3.11+ · MIT · zero runtime dependencies · alpha

```text
agent → JSON boundary → policy → keyed pseudonyms → hashed objects → evidence root
                           ↑                         ↓
                    same private key       strict replay → no tool invocation
```

## Run the incident, locally

```sh
python -m venv .venv
# Activate the environment for your shell, then:
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/incident.py
python -m replayseal verify demo-output/incident
python benchmarks/ablation.py
```

The synthetic example records a CRM lookup and invoice notification, replays them with zero live tool calls, and catches a regression that routes the invoice to a different customer. The output directory must be new: evidence is never silently overwritten. The published example keys and customer records are deliberately synthetic.

The example also emits `demo-output/incident.plan.json`. Run its data-only call contract through the CLI with the **public synthetic demo key**:

```powershell
# PowerShell; this published key is for synthetic demo records only.
$env:REPLAYSEAL_KEY = '7075626c69632d64656d6f2d6f6e6c792d7265706c6163652d6d652d303030303030'
python -m replayseal replay demo-output/incident demo-output/incident.plan.json
```

On POSIX shells use `export REPLAYSEAL_KEY=...` with the same demo hex value. Expected summary: `{"events": 2, "live_calls": 0, "recorded_errors": 0, "replayed": true}`. The plan passes the recorded lookup's customer and invoice into the next call using JSON Pointer result references; it never imports or executes tool implementations. Use SDK replay to exercise actual orchestration branches. Real keys come from your secret provisioning system, never from a published fixture.

## Wrap a tool boundary

```python
import os
from replayseal import Policy, Recorder, Replay

# Provision a private 32+ byte key; keep it outside fixtures and source control.
policy = Policy(bytes.fromhex(os.environ["REPLAYSEAL_KEY"]))

with Recorder("incident", policy) as rec:
    account = rec.call("crm.lookup", {"ticket": "t-17"},
                       lambda args: {"customer_id": "c-81", "invoice": "i-3"})
    rec.call("invoice.queue", account, lambda args: {"queued": True},
             depends_on=[rec.last_id])

with Replay("incident", policy, expected_root=rec.root) as replay:
    account = replay.call("crm.lookup", {"ticket": "t-17"})
    replay.call("invoice.queue", account, depends_on=[replay.last_id])
```

In a real integration, run the same orchestrator with either boundary object. A replay `call` accepts the same `invoke` argument as a recorder but never executes it. A mismatching tool, arguments, order or dependency poisons replay; later attempts fail. Leaving a replay context normally requires consuming every event. Repeated identical requests remain distinct ordered events, including their different recorded results.

`@boundary.tool("static.name")` wraps a synchronous JSON function and binds positional/keyword arguments plus defaults. Use explicit `call` for dependency edges. Exceptions become `RecordedToolError`, never dynamically imported exception classes. Recording executes the supplied function; replay executes only your orchestration code outside the boundary.

## Privacy that preserves the bug

Replacing every customer with `[REDACTED]` erases a cross-customer regression. HMAC-SHA-256 pseudonyms preserve equality and inequality while keeping the private key outside the evidence. The same key and policy reproduce the same sanitized signatures. Different keys deliberately produce incomparable recordings.

Defaults target explicitly named secret/identity fields, common email forms, bearer strings, and selected API-token formats. Extend them to fit your data:

```python
from replayseal.privacy import DEFAULT_FIELDS, DEFAULT_PATTERNS

policy = Policy(private_key,
    fields=(*DEFAULT_FIELDS, "phone", "session_id"),
    paths=("/arguments/people/*/name", "/result/billing/address"),
    patterns=(*DEFAULT_PATTERNS, r"\bSSN:\d{3}-\d{2}-\d{4}\b"))
```

Paths are JSON Pointers rooted at `arguments` or `result`; `*` matches one path segment. Exact field matching ignores case, spaces, underscores and hyphens. Array indices can be matched by a number or `*`. Matching fields hide the entire value, including its structure. Regexes match original strings, including dictionary keys; overlapping matches are merged before replacement. Exception messages always become opaque whole-message pseudonyms, and custom exception class names become `ToolError`. Rules are caller-trusted configuration. Unconfigured sensitive information can remain visible. **This is configurable pseudonymization, not a universal PII detector, anonymization certificate or legal compliance claim.**

## Inspect and share evidence

```sh
python -m replayseal verify incident --expected-root TRUSTED_ROOT_HEX
python -m replayseal diff before after
python -m replayseal export incident incident.seal.zip
# Extract the archive in a new folder, then independently:
python verify_bundle.py . --expected-root TRUSTED_ROOT_HEX
```

Verification checks content hashes, schema, signatures, contiguous event order and earlier-only causal references. `diff` reports the first event and JSON path that changed, without displaying the differing values. It refuses to treat different keys/policies as meaningful behavioral comparisons. CLI exit codes: **0** success/equal, **1** regression/difference, **2** invalid input or operation failure.

`replay TRACE PLAN --expected-root TRUSTED_ROOT_HEX` checks a complete ordered JSON plan, reading its hex key from `REPLAYSEAL_KEY`. `--key-env NAME` selects another variable and `--policy policy.json` supplies optional `fields`, `paths` and `patterns` arrays matching the recorder. CLI summaries omit result payloads and keys. Plans and policy files remain caller-owned: protect any raw arguments they contain. See the [plan schema and API](docs/FORMAT.md).

A bundle contains `manifest.json`, referenced `objects/<sha256>.json`, and a standalone standard-library verifier. Export is deterministic on the same runtime. Content hashes detect corruption; a root obtained from a trusted separate channel detects rewritten evidence. **Hashes alone do not authenticate the author or prove the events happened.**

## Scope and prior work

This is a deliberately narrow engineering combination: identity-preserving pre-persistence redaction, strict boundary replay, explicit causal edge checks and portable independently verifiable evidence. Recording, HMAC pseudonyms, content addressing and agent replay are established techniques. We claim no invention of those techniques and no world-first feature.

[VCR.py](https://vcrpy.readthedocs.io/en/latest/) already records/replays HTTP with configurable matching and filtering. [LangSmith](https://docs.langchain.com/langsmith/mask-inputs-outputs) already provides tracing, evaluations and several masking mechanisms. [OpenTelemetry](https://opentelemetry.io/docs/security/handling-sensitive-data/) supports telemetry pipelines and sensitive-data controls. [Chronicle](https://arxiv.org/abs/2609.20625) studies immutable boundary records and cut-point agent replay. Choose those systems for their respective established scope; this library concentrates on shareable, privacy-preserving **full** replay fixtures. See [the source-backed comparison](docs/PRIOR_ART.md) and [executable ablation](benchmarks/ablation.py).

No OS sandbox, network interception, asynchronous/distributed replay, live cut-point execution, automatic causal inference or proof that a model's answer is correct. Only calls routed through the boundary are controlled. Opaque redacted values support equality and pass-through; code that transforms a real secret or branches on its length needs a deliberately designed synthetic fixture. See [threat boundaries](SECURITY.md), [format/API](docs/FORMAT.md), [measurements](docs/BENCHMARKS.md) and [review iterations](docs/ITERATIONS.md).

## 中文说明

**把智能体工具调用事故变成可分享、可复现的回归证据。** replayseal 在落盘前对配置命中的秘密与个人标识进行带密钥的稳定假名化；同一客户仍可识别为同一客户，不同客户不会都被压成一个 `[REDACTED]`，因此能保留“误发给另一位客户”这类问题。

SDK 支持上下文管理器、函数装饰器和显式工具边界。回放严格检查工具名称、结构化参数、先后顺序和显式因果依赖；不调用传入的真实工具函数。CLI 可执行纯 JSON 回放计划、校验记录、定位两个版本的首个差异、导出内置独立校验器的证据 ZIP。计划可引用前面已成功调用的结果，输出摘要不展示客户数据或密钥；实际业务分支仍应通过 SDK 验证。示例完全离线，不发送邮件、不请求模型、不需要 API 凭据。

默认规则并不覆盖所有个人信息。请为业务字段、数组路径和自定义格式配置规则，并用合成样本检查；密钥不得随证据提交。内容哈希用于发现损坏，需要通过可信渠道保存根哈希才能发现整份证据被重写。它不证明记录者身份，也不等同于沙箱或合规认证。

适合负责智能体质量、客户事故复现和 CI 的工程团队。当前为范围明确的早期工具，尚无实际客户、收入或独立安全认证；商业价值论证与性能测量均注明假设，不将合成测试当作市场验证。

## Contribute

Run the tests and the offline incident before opening a change. Add adversarial cases for behavior changes. Do not submit real customer traces or private keys. See [CONTRIBUTING.md](CONTRIBUTING.md); licensed under [MIT](LICENSE).
