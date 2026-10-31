# Contributing Guidelines

Contributions to **PolytopeBarrierVerifier** must preserve deterministic integer arithmetic and 100% validator soundness.

## Pre-Submission Checklist

1. Ensure zero floating-point operations are introduced into `PolytopeBarrierVerifier.py`.
2. Verify that all schema bounds, duplicate-key guards, and Farkas witness checks remain fail-closed.
3. Run the local test suite without external network calls:

    pytest test.py -v
