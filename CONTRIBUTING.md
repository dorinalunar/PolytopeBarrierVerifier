# Contributing Guidelines

Contributions to **PolytopeBarrierVerifier** must preserve deterministic integer arithmetic and 100% validator soundness.

## Pre-Submission Checklist

1. Ensure zero floating-point operations are introduced into `PolytopeBarrierVerifier.py`.
2. Verify that all schema bounds, duplicate-key guards, and Farkas witness checks remain fail-closed.
3. Add any new benchmark systems to `sample_dataset.json` and run the local test suite:

    pytest test_polytope_barrier.py -v
