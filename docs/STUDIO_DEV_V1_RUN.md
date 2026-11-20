# UptimeShield — Reference Lifecycle Walkthrough

End-to-end execution trace of `UptimeShield.py` on GenLayer Studio Dev (`chain 61997`), demonstrating vault creation, domain attestation verification, subscriber terms commitment, multi-round consensus resolution, deadline expiry, and pull-based payouts.

## Lint & Verification

```bash
pip install genvm-linter
sh scripts/lint_current_sdk.sh
```

`genvm-lint lint`, `check`, and `typecheck` validate `contracts/UptimeShield.py` directly against the `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` SDK target deployed at `0x601B470288Dd14422f4A4bA3D44871F906Bb6864` on Studio Dev (`chain 61997`).

## Walkthrough Scenario

| Step | Action | Caller | Expected Outcome |
|---|---|---|---|
| 1 | `create_vault("api-sla-1", ...)` with `4 GEN` | Sponsor | Vault opens in `open` state with `source_attested: true` when `/.well-known/genlayer-status.json` lists `status_url` and `service_name`. |
| 2 | `create_vault("spoof-1", ...)` with cross-host URL | Attacker | Rejected with `"the status page must be under the provider site"`; `4 GEN` credited to `refund_credits`. |
| 3 | `subscribe_protection("api-sla-1", wrong_hash)` with `0.5 GEN` | User B | Rejected with `"the confirmed terms do not match this vault's terms"`; `0.5 GEN` credited. |
| 4 | `subscribe_protection("api-sla-1", terms_hash)` with `0.5 GEN` | User A | Recorded in `subscriptions["api-sla-1"]`; `max_liability` increases by `0.5 * payout_multiplier`. |
| 5 | `resolve_round("api-sla-1")` (Round 1) | Keeper | Validators fetch `status_url` and re-verify `.well-known/genlayer-status.json`; consensus returns `incident` (`proposed`, `confirmations = 1`). |
| 6 | `resolve_round("api-sla-1")` (Round 2, after `resolution_interval`) | Keeper | Consensus confirms `incident` (`confirmations = 2 == rounds_required`); vault transitions to `breached`. |
| 7 | `claim_payout("api-sla-1")` | User A | Transfers `0.5 * payout_multiplier` GEN to User A and marks subscription `claimed = true`. |
| 8 | `withdraw_sponsor_reserve("api-sla-1")` | Sponsor | Transfers remaining unencumbered reserve + deposits back to Sponsor; contract balance reconciles to `0`. |
