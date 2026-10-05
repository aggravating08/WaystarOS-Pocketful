# Pocketful — Dark Factory Hackathon

**Track**: Pocketful (Digital Wallet & Payments App)  
**Status**: Stages 1–4 Completed & Verified (Highest contiguous stage: 4)

This repository contains the output of the BAND autonomous software factory for the **Pocketful** track of the Dark Factory Hackathon.

## Contents
- `stage-1/`: Complete Stage 1 JSON API service implementation (`server.py`), `Dockerfile`, and `RUN.md`.
- `stage-2/`: Interactive Single-Page Web Application UI (HTML/CSS/vanilla JS) and Authorizations/Holds service (`server.py`), `Dockerfile`, and `RUN.md`.
- `stage-3/`: Effective vs recorded time, payment corrections, historical statements, and immutable snapshot pagination service (`server.py`), `Dockerfile`, and `RUN.md`.
- `stage-4/`: Refunds and atomic settlement batch corrections service (`server.py`), `Dockerfile`, and `RUN.md`.
- `mandates/`: Generic, track-independent agent mandates for Coordinator, Implementer, Verifier, and Release Reviewer.
- `room.json`: Complete session event log capturing the collaboration, handoffs, and verification between seats.
- `FACTORY.md`: Factory design, execution summary, and verification measurements.

## Verification
- Official Harness check: **Passed** (All gates verified).
- Official Harness run: **Stages 1–4 Passed** across all shipped tests and upgrade migrations.
- Container conformance: Runs clean under Docker resource limits (2 vCPU, 2 GiB).
