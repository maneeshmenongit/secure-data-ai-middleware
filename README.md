# DataSec middleware

Provenance-first security core for AI apps: trust travels with the data, every sink goes
through one `SecurityPipeline.guard()` call, and every decision lands in a hash-chained audit log.
Stdlib-only at runtime. Design: [DESIGN.md](DESIGN.md) ·
Phase 1 spec: [docs/superpowers/specs/2026-09-27-datasec-core-design.md](docs/superpowers/specs/2026-09-27-datasec-core-design.md)

## Quickstart

```bash
uv sync
uv run pytest                 # unit tests + red-team suite
uv run python demo.py         # 4 end-to-end scenarios
uv run python -m redteam.runner   # attack scorecard -> redteam/scorecard.json
```

```python
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action
from datasec.provenance import from_user

pipeline = SecurityPipeline()
msg = from_user("Email me at jane@example.com", source="user:req-42")
result = pipeline.guard(Action("llm", "chat", msg.provenance), msg.value)
result.payload   # 'Email me at [EMAIL]'
```

## Configuration (Phase 2)

```python
import os

from datasec.audit import AuditLog
from datasec.crypto import LocalKeyProvider          # pip install 'datasec[crypto]'
from datasec.pipeline import SecurityPipeline
from datasec.policy import PolicyEngine, default_rules

# Key material must outlive the process: a fresh random key on every start makes old
# checkpoints and sealed data unreadable, and AuditLog will (correctly) refuse to start.
# Generate once: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
keys = LocalKeyProvider({"k1": os.environb[b"DATASEC_KEY_K1"]})
pipeline = SecurityPipeline(
    engine=PolicyEngine(default_rules(
        egress_allowlist={"api.stripe.com"},              # empty = deny every named destination
        privileged_source_allowlist={"api:stripe-verified"},  # EXTERNAL sources only
    )),
    audit=AuditLog("audit.jsonl", signer=keys, checkpoint_path="audit.checkpoint"),
    key_provider=keys,        # secret memory writes are sealed at rest
    max_bytes=1_000_000, max_depth=200,
)
# Action(..., destination="api.stripe.com")  names an egress host
# Action(..., scan_integers=True)            opts a call into integer PII scanning
```

Call `pipeline.audit.close()` on shutdown (or use `with AuditLog(...) as log:`) to write the final signed checkpoint. Entries appended
after the last checkpoint are protected only by the chain until the next one is written.

## Red-team suite

`redteam/attacks/` attacks the core in-process (no network). Each attack expects an outcome:
`blocked`, `redacted`, `detected`, `bounded`, `encrypted`, `allowed` (must not over-block), or `known_gap`. Known gaps are strict xfails —
fixing one fails the build until its label is updated. Current known gaps:

- Hand-built `Provenance(TRUSTED, ...)` for untrusted data (Python can't prevent it).
- PII written in words or split across list items (regex limit; Presidio later).
- Audit tail truncation / full-chain rewrite **when no signed checkpoint (or pinned head) is configured**.
- Replaying an older genuine checkpoint after truncating the tail (needs a monotonic anchor outside the attacker's reach).
