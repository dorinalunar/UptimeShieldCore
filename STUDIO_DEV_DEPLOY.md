# UptimeShield v2 — GenLayer Studio Dev (`chain 61997`) Deployment Guide

| Field | Value |
|---|---|
| **Network** | GenLayer Studio Dev — chain `61997` (`https://studio-dev.genlayer.com/api`) |
| **Deployed Address** | [`0x601B470288Dd14422f4A4bA3D44871F906Bb6864`](https://explorer-studio-dev.genlayer.com/address/0x601B470288Dd14422f4A4bA3D44871F906Bb6864) |
| **Contract Source** | [`contracts/UptimeShield.py`](contracts/UptimeShield.py) |
| **GenVM Runner** | `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` |
| **Source SHA-256** | `480a5154795be7becbe2658dc12df94c44a4b9ad11588d5b4a6acb42850a5d0c` |
| **Author** | Andrii Efimenko (`@dorinalunar`) |

## Architecture & Hardening Summary

| Area | Implementation in `UptimeShield.py` |
|---|---|
| **Source Attestation** | `create_vault` validates that `status_url` is strictly nested under `provider_origin` and reads `provider_origin + /.well-known/genlayer-status.json`. Vaults are marked `source_attested: true` only when the JSON lists both `status_url` and `service_name`. Every `resolve_round` re-fetches the attestation and returns `inconclusive` (`attestation_missing`) if it disappears. |
| **Terms Commitment** | `compute_vault_terms_hash` hashes `vault_id`, `service_name`, `provider_origin`, `status_url`, `sla_rule`, `source_attested`, `subscription_closes_at`, `protection_ends_at`, `payout_multiplier`, `resolution_interval`, and `rounds_required`. `subscribe_protection` rejects mismatched hashes and credits attached GEN. |
| **Deadline Determinism** | `compute_resolution_deadline` sets `protection_ends_at + (rounds_required + 3) * resolution_interval`. `resolve_round` reverts at or after this timestamp; `expire_vault` reverts before it. |
| **Bounded Evidence & Complete-Page Rule** | `extract_bounded_digest` keeps pages `<= 4000` chars whole (`covers_whole_document = true`) and slices longer pages into up to 6 deterministic 500-char windows. `clean` verdicts from partial excerpts are downgraded to `inconclusive` (`clean_from_incomplete_page`). |
| **Persistent Round Artifacts** | Every round is stored in `audit_rounds[vault_id#round]` with full-page SHA-256, excerpt SHA-256, exact excerpt slices, attestation snapshot, injection flags, and verdict. |
| **Pull Accounting** | Rejected payable calls credit `refund_credits[sender]`. `claim_payout` and `withdraw_sponsor_reserve` update internal ledgers before emitting external native GEN transfers via `_ExternalAccount.emit_transfer`. |

## Verify Source Integrity

```bash
shasum -a 256 contracts/UptimeShield.py
# Expected: 480a5154795be7becbe2658dc12df94c44a4b9ad11588d5b4a6acb42850a5d0c
```

Once deployed on Studio Dev (`chain 61997`), verify on-chain bytecode parity:

```bash
export UPTIMESHIELD_ADDRESS="0x601B470288Dd14422f4A4bA3D44871F906Bb6864"
python3 scripts/verify_deployment.py
```

## Demo Provider Fixtures

- **Attested provider (`beacon`)**: `https://raw.githubusercontent.com/dorinalunar/UptimeShieldCore/main/fixtures/providers/beacon` publishes [`.well-known/genlayer-status.json`](fixtures/providers/beacon/.well-known/genlayer-status.json) listing `nominal.html`, `history.html`, and `api.html`.
- **Unattested mirror (`shadow`)**: `https://raw.githubusercontent.com/dorinalunar/UptimeShieldCore/main/fixtures/providers/shadow` publishes no `.well-known` attestation and opens vaults with `source_attested: false`.

## Standard Lifecycle Sequence

1. **Create Vault (`create_vault`)**: Sponsor attaches `>= 1 GEN` (`1000000000000000000` wei) and commits `provider_origin`, `status_url`, `sla_rule`, windows, `payout_multiplier`, `resolution_interval`, and `rounds_required`.
2. **Subscribe (`subscribe_protection`)**: Subscriber reads `get_terms_hash(vault_id)` and attaches deposit `D` (`D * payout_multiplier <= free_capacity`).
3. **Adjudicate (`resolve_round`)**: Any keeper calls `resolve_round(vault_id)` after `protection_ends_at` and before `resolution_deadline` until `rounds_required` consecutive agreeing rounds settle the vault as `breached` or `nominal` (or `expire_vault` transitions it to `expired` at the deadline).
4. **Settle Funds**: Subscribers call `claim_payout(vault_id)`, sponsors call `withdraw_sponsor_reserve(vault_id)`, and senders with rejected deposits call `withdraw_credit()`.
