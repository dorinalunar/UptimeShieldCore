# UptimeShield

<p align="center">
  <strong>Parametric SLA & outage protection settled on-chain by GenLayer validator consensus over a provider's authoritative status endpoint.</strong>
</p>

<p align="center">
  <a href="https://github.com/dorinalunar/UptimeShieldCore/actions/workflows/ci.yml"><img src="https://github.com/dorinalunar/UptimeShieldCore/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/GenLayer-Studio%20Dev%2061997-38bdf8?style=flat-square" alt="Studio Dev" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="MIT" /></a>
</p>

---

## Overview

Conventional SLA claims and outage insurance suffer from an oracle bottleneck: numeric price feeds cannot verify whether an API status page reported a 47-minute major outage inside a coverage window, while centralized underwriters introduce discretionary claim denials.

**UptimeShield** turns *"did the provider's own status page report a qualifying SLA breach during the protection period?"* into a deterministic, multi-round validator consensus question on GenLayer (`chain 61997`). All protection parameters, domain attestation checks, bounded excerpt rules, and payout multipliers are locked on-chain when a vault is created.

## Trust Model & Source Attestation

| Vault Classification | Verification Rule | Trust Assumption |
|---|---|---|
| **ATTESTED** | The `provider_origin` serves `/.well-known/genlayer-status.json` listing both `status_url` and `service_name`. Validators verify this file at `create_vault` **and re-verify it in every `resolve_round`**. | Domain administrator controlling `provider_origin`. Cross-host URLs are rejected on creation; if the attestation disappears or stops listing the page mid-settlement, the round resolves as `inconclusive`. |
| **UNATTESTED** | The provider serves no `.well-known/genlayer-status.json` file. Allowed, with `source_attested: false` stored on-chain and hashed into `terms_hash`. | The sponsor's choice of `status_url`. Subscribers verify the URL before committing `confirmed_terms_hash`. |

## Core Lifecycle

```
create_vault(vault_id, service_name, provider_origin, status_url, sla_rule,
             subscription_window, protection_duration, payout_multiplier,
             resolution_interval, rounds_required)                        PAYABLE (>= 1 GEN)
subscribe_protection(vault_id, confirmed_terms_hash)                      PAYABLE
resolve_round(vault_id)   permissionless after protection ends and strictly BEFORE resolution_deadline:
                            incident      -> proposes or confirms "incident"
                            clean         -> valid ONLY when validators read the whole page
                            inconclusive  -> advances round counter without changing proposal
                          rounds_required agreeing rounds -> BREACHED or NOMINAL
expire_vault(vault_id)    permissionless AT or after resolution_deadline -> EXPIRED (full refund)
claim_payout / withdraw_sponsor_reserve / withdraw_credit                 pull settlement
get_round(vault_id, n)    immutable round evidence artifact (hashes, excerpts, attestation)
list_vaults(offset, limit)                                                paginated vault index
```

## Security Guarantees

| Threat / Edge Case | Enforcement Mechanism |
|---|---|
| Spoofed status page under a legitimate provider name | `status_url` must reside at or beneath `provider_origin`. Attested vaults require `/.well-known/genlayer-status.json` to explicitly list both `status_url` and `service_name`. |
| Attestation revoked or domain hijacked before resolution | `verify_domain_attestation` runs again in every `resolve_round`; missing or mismatched attestation forces `inconclusive` (`attestation_missing`) before querying any LLM. |
| False `clean` verdict from truncated long pages | `clean` is accepted only when `covers_whole_document` is `True`. A `clean` model output on partial excerpts is downgraded to `inconclusive` (`clean_from_incomplete_page`). |
| Race condition at the settlement boundary | `resolve_round` is accepted strictly before `resolution_deadline`; `expire_vault` is accepted at or after `resolution_deadline`. `get_schedule` exposes mutually exclusive flags. |
| Ephemeral status pages edited or deleted post-incident | Every round persists `provider_origin`, `status_url`, fetch status, timestamp, full-document SHA-256, excerpt SHA-256, exact excerpt slices, attestation record, and verdict in `audit_rounds`. |
| Unbounded registry growth | Indexed via `TreeMap[str, str]` and `DynArray[str]` with `list_vaults(offset, limit)` pagination (capped at `MAX_PAGE_LIMIT = 50`) and a 1 GEN minimum reserve deposit. |
| Prompt injection inside status HTML | Fetched text is wrapped inside `<<<BEGIN_UNTRUSTED_DATA>>>` / `<<<END_UNTRUSTED_DATA>>>` fences, scanned for injection markers, and restricted to exact JSON literals (`"incident"`, `"clean"`, `"inconclusive"`). |
| Value stranded on rejected payable calls | `create_vault` and `subscribe_protection` catch validation failures once value is attached and credit the full amount to `refund_credits` for withdrawal via `withdraw_credit()`. |

## Live Deployment (Studio Dev — Chain `61997`)

- **Contract Address:** [`0x601B470288Dd14422f4A4bA3D44871F906Bb6864`](https://explorer-studio-dev.genlayer.com/address/0x601B470288Dd14422f4A4bA3D44871F906Bb6864)
- **Import in Studio Dev:** [Open in GenLayer Studio Dev](https://studio-dev.genlayer.com/?import-contract=0x601B470288Dd14422f4A4bA3D44871F906Bb6864)
- **Source SHA-256:** `480a5154795be7becbe2658dc12df94c44a4b9ad11588d5b4a6acb42850a5d0c`

## Repository Layout

- [`contracts/UptimeShield.py`](contracts/UptimeShield.py) — Intelligent Contract (`py-genlayer`, SHA-256 `480a5154795be7becbe2658dc12df94c44a4b9ad11588d5b4a6acb42850a5d0c`)
- [`tests/conftest.py`](tests/conftest.py) & [`tests/test_uptimeshield.py`](tests/test_uptimeshield.py) — Deterministic GenVM test harness & full security test suite
- [`fixtures/providers/beacon`](fixtures/providers/beacon) & [`fixtures/providers/shadow`](fixtures/providers/shadow) — Attested and unattested provider status fixtures
- [`STUDIO_DEV_DEPLOY.md`](STUDIO_DEV_DEPLOY.md) — Deployment configuration & verification guide for GenLayer Studio Dev (`chain 61997`)
- [`docs/STUDIO_DEV_V1_RUN.md`](docs/STUDIO_DEV_V1_RUN.md) — Reference lifecycle walkthrough

## Running Tests & Linter

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
sh scripts/lint_current_sdk.sh
```

## License

[MIT](LICENSE) © 2026 Andrii Efimenko (`@dorinalunar`)
