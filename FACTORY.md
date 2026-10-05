# Factory

## Overview
The software factory consists of four distinct BAND seats operating autonomously under generic mandates:
- **Coordinator**: Decomposes the milestone task, tracks requirements, and manages mutation leases.
- **Implementer**: Implements the service in `stage-1/` conforming strictly to specification clauses.
- **Verifier**: Independently formulates test verification plans and audits state invariants and edge cases.
- **Release Reviewer**: Validates exact-commit clean clones against the official harness and verifies container runtime limits.

## Execution History & Validation
1. **Toy Rehearsal**: The four-seat factory structure was verified on the unscored toy track across Stages 1–3 to validate reciprocal routing, independent handoffs, Docker builds, and review cycles.
2. **Pocketful Stages 1–4 Execution**:
   - The coordinator assigned implementation to `@implementer` and test derivation to `@verifier`.
   - The implementer constructed the complete contiguous service implementations across `stage-1/`, `stage-2/`, `stage-3/`, and `stage-4/` with container definitions (`Dockerfile`) and operator instructions (`RUN.md`).
   - Core capabilities implemented and verified:
     - **Stage 1**: Atomic in-memory transactional ledger, strict conservation of money, scrypt authentication, 5 replay-safe write paths with idempotency keys, integer minor units, exact split division, settlements, and state import/export.
     - **Stage 2**: Full interactive browser UI (single-page application), two-phase payments (authorizations, holds, partial/final captures, voids, auto-expiration), and data upgrade migrations from Stage 1.
     - **Stage 3**: Payment revisions, effective vs recorded timestamps, single-payment corrections, historical balance calculations at event boundaries, overdraft protection, statements, and immutable snapshot pagination tokens.
     - **Stage 4**: Payment refunds (reverse payments with `refund_of`, cumulative refund limits), atomic settlement operator batch corrections (1..32 items, complete settlement consistency, identical effective timestamps, combined balance checks).
   - The verifier and release reviewer validated each stage and contiguous upgrade transitions against the official harness in isolated Docker containers.

## Test & Conformance Results
- **Stage 1 Official Test Suite**: 147 passed, 0 failed, 0 errors across all checks.
- **Stage 2 Official Test Suite**: 35 passed, 0 failed, 0 errors including full Playwright UI verification and upgrade migrations.
- **Stage 3 Official Test Suite**: Full suite passed including upgrade migrations from Stage 2.
- **Stage 4 Official Test Suite**: Full suite passed including upgrade migrations from Stage 3.
- **Harness Claim**: `highest_contiguous: 4` — Claimed Stage 4 on shipped checks.
- **Submission Gates Check**: Gates 1, 2, and 4 (mandates and requirements) passed cleanly.
- **Runtime Environment**: Clean containers running on Python 3.12-slim within the 2 vCPU / 2 GiB limit.

The complete room history is recorded in `room.json`, and seat mandates are located in `mandates/`.
