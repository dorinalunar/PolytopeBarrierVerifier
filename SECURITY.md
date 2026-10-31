# Security Policy & Formal Soundness Guarantees

## Deterministic Consensus Safety

`PolytopeBarrierVerifier.py` separates non-deterministic AI proof search from deterministic algebraic verification:

1. **Untrusted LLM Output:** Candidate invariants and dual weights returned by `gl.nondet.exec_prompt` are treated as untrusted input.
2. **Exact Integer Arithmetic:** Validators verify conic combinations using exact Python integers (`sum(w_i * a_ij) == scale * target_j`), eliminating IEEE-754 rounding errors.
3. **JSON Deserialization Hardening:** Payloads are restricted to 4,096 bytes for system definitions and 12,000 bytes for certificates. Duplicate JSON keys are rejected at parse time via `_unique_kv_pairs`.
4. **Replay & Substitution Protection:** Every synthesis envelope binds the `protocol` version, `contract` address, `system_id`, `system_root`, `model_hash`, `caller`, and sequential `trial` index.

## Reporting a Vulnerability

If you discover an algebraic soundness bypass or input validation issue, please open a GitHub issue with a minimal reproducible JSON payload and test case.
