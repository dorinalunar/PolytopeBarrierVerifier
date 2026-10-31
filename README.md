# PolytopeBarrierVerifier — GenLayer Intelligent Contract

**PolytopeBarrierVerifier** is an autonomous formal verification registry and AI-guided invariant synthesis engine built for the **GenLayer** ecosystem. It synthesizes inductive polyhedral barrier certificates for discrete-time affine transition systems using GenVM non-deterministic LLM execution (`gl.nondet.exec_prompt`) while enforcing 100% deterministic, zero-floating-point algebraic soundness via Farkas' Lemma in validators.

---

## Core Architecture & Key Features

1. **Neuro-Symbolic Verification Pipeline:**
   * **Leader Proposal (AI Synthesis):** Queries an LLM inside GenVM to propose a candidate polyhedral barrier $P = \{x \in \mathbb{Z}^d \mid A x \le b\}$ alongside non-negative integer dual multipliers (Farkas witnesses) for initiation, consecution (inductive step), and safety.
   * **Validator Verification (Exact Integer Linear Algebra):** Validators never re-run creative LLM generation or trust probabilistic claims. Instead, each validator deterministically checks exact integer vector identities and halfspace bound implications in $O(m \cdot d)$ operations.
2. **Zero Floating-Point Drift:**
   * All state vectors, transformation matrices, halfspace normals, and dual multipliers use bounded mathematical integers (`scale` $\in [1, 1000]$, `weights` $\in [0, 10000]$).
3. **Cryptographic Commitment Roots:**
   * Every registered dynamical system and verified barrier certificate is canonicalized and hashed with SHA-256 (`state_root`, `model_hash`, `cert_root`), enabling trustless cross-contract or off-chain theorem auditing via `export_verified_claim()`.
4. **Fail-Closed Input & Resource Guards:**
   * Strict JSON byte caps, duplicate-key rejection, anchor seed containment checks, per-author system quotas (`32`), and bounded synthesis trials (`3` per system).

---

## Repository Structure

* `PolytopeBarrierVerifier.py` — GenLayer Intelligent Contract implementation.
* `sample_dataset.json` — Reference 1D and 2D affine transition systems and verified Farkas barrier certificates.
* `test_polytope_barrier.py` — End-to-end `pytest` unit test suite with local GenVM mock and dataset verification.
* `SECURITY.md` — Formal soundness and input validation policy.
* `CONTRIBUTING.md` — Developer guidelines.

---

## Contract Public Interface

### Write Methods
* `publish_system(tag_nonce: str, system_json: str) -> str`
  Validates and registers a formal affine transition system, returning its deterministic `system_id`.
* `generate_certificate(system_id: str, expected_trial: int) -> str`
  Executes GenVM non-deterministic synthesis with self-repair and deterministic Farkas validation, storing the verified certificate under `cert_id`.

### View Methods
* `get_system(system_id: str) -> dict` — Returns the canonical system specification and SHA-256 roots.
* `get_certificate(cert_id: str) -> dict` — Returns the verified barrier certificate and context binding.
* `get_trial_count(system_id: str) -> int` — Returns the number of synthesis trials consumed for `system_id`.
* `verify_certificate_offline(system_id: str, candidate_cert_json: str) -> bool` — Statelessly checks any candidate certificate JSON against a registered system.
* `export_verified_claim(cert_id: str, expected_system_root: str, expected_cert_root: str) -> dict` — Re-verifies stored proof obligations and exports a root-pinned safety theorem.

---

## Local Testing & Verification

Install dependencies and run the deterministic `pytest` suite:

    pip install -r requirements.txt
    pytest test_polytope_barrier.py -v

---

## License

Released under the MIT License. See `LICENSE` for details.