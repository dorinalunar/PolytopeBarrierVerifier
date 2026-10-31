# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import hashlib
import json
import re
from genlayer import *

PROTOCOL_VERSION = "polytope-barrier-verifier-v1"

MAX_SYSTEM_BYTES = 4096
MAX_CERT_BYTES = 12000
MAX_AUTHOR_SYSTEMS = 32
MAX_SYNTHESIS_TRIALS = 3


def _canonical_json(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_digest(payload) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _unique_kv_pairs(pairs_list):
    out = {}
    for k, v in pairs_list:
        if k in out:
            raise ValueError("Duplicate key in JSON object")
        out[k] = v
    return out


def _decode_bounded_json(raw_input, byte_limit: int):
    if not isinstance(raw_input, str):
        raise ValueError("Payload must be a string")
    encoded_len = len(raw_input.encode("utf-8"))
    if encoded_len < 1 or encoded_len > byte_limit:
        raise ValueError("Payload byte length out of bounds")
    cleaned = raw_input[5:] if raw_input.startswith("json:") else raw_input
    return json.loads(cleaned, object_pairs_hook=_unique_kv_pairs)


def _require_schema_keys(obj, expected_keys):
    if not isinstance(obj, dict) or set(obj.keys()) != set(expected_keys):
        raise ValueError("Schema field mismatch")


def _require_int_range(val, low: int, high: int) -> int:
    if type(val) is not int or val < low or val > high:
        raise ValueError("Integer value out of range")
    return val


def _require_int_vector(vec, expected_dim: int, abs_bound: int) -> list:
    if not isinstance(vec, list) or len(vec) != expected_dim:
        raise ValueError("Vector dimension mismatch")
    return [_require_int_range(item, -abs_bound, abs_bound) for item in vec]


def _require_halfspace_constraints(rows_list, dim: int, max_rows: int, coeff_limit: int, rhs_limit: int) -> list:
    if not isinstance(rows_list, list) or not (1 <= len(rows_list) <= max_rows):
        raise ValueError("Constraint row count out of bounds")
    for item in rows_list:
        _require_schema_keys(item, ["a", "b"])
        _require_int_vector(item["a"], dim, coeff_limit)
        _require_int_range(item["b"], -rhs_limit, rhs_limit)
        if not any(item["a"]):
            raise ValueError("Degenerate zero normal vector")
    return rows_list


def _inner_product(vec_left: list, vec_right: list) -> int:
    return sum(x * y for x, y in zip(vec_left, vec_right))


def _parse_dynamical_system(raw_json: str) -> dict:
    parsed = _decode_bounded_json(raw_json, MAX_SYSTEM_BYTES)
    _require_schema_keys(
        parsed,
        ["dimension", "initial", "guard", "matrix", "offset", "safety", "seed"],
    )
    dim = _require_int_range(parsed["dimension"], 1, 2)
    _require_halfspace_constraints(parsed["initial"], dim, 4, 100, 10000)
    _require_halfspace_constraints(parsed["guard"], dim, 3, 100, 10000)
    _require_halfspace_constraints(parsed["safety"], dim, 2, 100, 10000)
    _require_int_vector(parsed["offset"], dim, 100)
    _require_int_vector(parsed["seed"], dim, 10000)

    mat = parsed["matrix"]
    if not isinstance(mat, list) or len(mat) != dim:
        raise ValueError("Transition matrix dimension mismatch")
    for row in mat:
        _require_int_vector(row, dim, 10)

    if any(_inner_product(constraint["a"], parsed["seed"]) > constraint["b"] for constraint in parsed["initial"]):
        raise ValueError("Anchor seed violates initial polytope")
    return parsed


def _verify_farkas_combination(source_rows: list, target_row: dict, dual_witness: dict) -> None:
    """Deterministic exact integer Farkas certificate check without floating-point arithmetic."""
    _require_schema_keys(dual_witness, ["weights", "scale"])
    denominator = _require_int_range(dual_witness["scale"], 1, 1000)
    multipliers = dual_witness["weights"]

    if not isinstance(multipliers, list) or len(multipliers) != len(source_rows):
        raise ValueError("Dual multiplier count mismatch")
    for m in multipliers:
        _require_int_range(m, 0, 10000)

    for coord_idx, target_coeff in enumerate(target_row["a"]):
        weighted_sum = sum(multipliers[row_idx] * src["a"][coord_idx] for row_idx, src in enumerate(source_rows))
        if weighted_sum != denominator * target_coeff:
            raise ValueError("Normal vector conic combination mismatch")

    weighted_rhs = sum(m * src["b"] for m, src in zip(multipliers, source_rows))
    if weighted_rhs > denominator * target_row["b"]:
        raise ValueError("Halfspace offset implication violated")


def _verify_barrier_certificate(sys_model: dict, raw_cert) -> dict:
    cert = _decode_bounded_json(raw_cert, MAX_CERT_BYTES) if isinstance(raw_cert, str) else raw_cert
    if len(_canonical_json(cert).encode("utf-8")) > MAX_CERT_BYTES:
        raise ValueError("Serialized certificate exceeds limit")

    _require_schema_keys(cert, ["invariant", "initial", "step", "safety"])
    dim = sys_model["dimension"]
    barrier_rows = _require_halfspace_constraints(cert["invariant"], dim, 3, 1000, 10000)

    expected_obligations = [
        ("initial", len(barrier_rows)),
        ("step", len(barrier_rows)),
        ("safety", len(sys_model["safety"])),
    ]
    for section_key, required_len in expected_obligations:
        if not isinstance(cert[section_key], list) or len(cert[section_key]) != required_len:
            raise ValueError("Proof obligation list length mismatch")

    for idx, barrier_row in enumerate(barrier_rows):
        _verify_farkas_combination(sys_model["initial"], barrier_row, cert["initial"][idx])

        pulled_back_normal = [
            sum(barrier_row["a"][k] * sys_model["matrix"][k][col] for k in range(dim))
            for col in range(dim)
        ]
        pulled_back_rhs = barrier_row["b"] - _inner_product(barrier_row["a"], sys_model["offset"])
        pulled_back_target = {"a": pulled_back_normal, "b": pulled_back_rhs}

        _verify_farkas_combination(
            barrier_rows + sys_model["guard"],
            pulled_back_target,
            cert["step"][idx],
        )

    for idx, safe_row in enumerate(sys_model["safety"]):
        _verify_farkas_combination(barrier_rows, safe_row, cert["safety"][idx])

    return cert


def _compose_synthesis_prompt(sys_model: dict) -> str:
    return (
        "POLYTOPE_BARRIER_SYNTHESIS_V1\n"
        "Construct an inductive polyhedral barrier proving safety of the discrete affine system.\n"
        "State variables are unbounded mathematical integers. Each halfspace {a:[...],b:B} encodes a dot x <= B.\n"
        "All initial constraints hold simultaneously. A transition x_next = matrix * x + offset fires only when\n"
        "every guard constraint holds. Every reachable state must satisfy all safety constraints.\n"
        "Output strictly valid JSON with four top-level keys:\n"
        '{"invariant":[{"a":[...],"b":0}],"initial":[{"weights":[...],"scale":1}],'
        '"step":[{"weights":[...],"scale":1}],"safety":[{"weights":[...],"scale":1}]}\n'
        "Rules:\n"
        "1. Select 1..3 invariant rows with nonzero integer normal vectors (|a_i| <= 1000) and |b| <= 10000.\n"
        "2. Every dual witness uses integer weights in 0..10000 and integer scale in 1..1000.\n"
        "3. For source rows S and target row T: sum(weights_i * S_i.a) == scale * T.a coordinate-wise, and\n"
        "   sum(weights_i * S_i.b) <= scale * T.b.\n"
        "4. initial[i] derives invariant[i] from initial rows.\n"
        "5. step[i] derives {a: invariant[i].a * matrix, b: invariant[i].b - invariant[i].a dot offset}\n"
        "   from (invariant rows followed by guard rows).\n"
        "6. safety[i] derives safety[i] from invariant rows.\n"
        "Return raw JSON only with no markdown or commentary.\n"
        "SYSTEM_SPEC_JSON:\n"
        + _canonical_json(sys_model)
    )


def _validate_signed_envelope(envelope: dict, context_binding: dict, sys_model: dict) -> dict:
    _require_schema_keys(envelope, ["binding", "proof"])
    if _canonical_json(envelope["binding"]) != _canonical_json(context_binding):
        raise ValueError("Context binding mismatch")
    return _verify_barrier_certificate(sys_model, envelope["proof"])


def _run_consensus_synthesis(context_binding: dict, sys_model: dict) -> dict:
    def leader_propose():
        active_prompt = _compose_synthesis_prompt(sys_model)
        for _ in range(2):
            raw_candidate = None
            try:
                raw_candidate = gl.nondet.exec_prompt(active_prompt, response_format="json")
                verified_cert = _verify_barrier_certificate(sys_model, raw_candidate)
                return {"binding": context_binding, "proof": verified_cert}
            except Exception as err:
                diag = str(err) if isinstance(err, ValueError) else type(err).__name__
                print("[BARRIER_SYNTHESIS_DIAG] " + diag[:80])
                active_prompt = (
                    _compose_synthesis_prompt(sys_model)
                    + "\nFix the algebraic witness failure for the exact system above.\n"
                    + "VERIFIER_DIAGNOSTIC: "
                    + diag[:80]
                    + "\nPRIOR_CANDIDATE: "
                    + _canonical_json(raw_candidate)[:MAX_CERT_BYTES]
                )
        raise gl.vm.UserError("[SYNTH_FAULT] Unable to synthesize a valid Farkas barrier certificate")

    def validator_check(leader_result) -> bool:
        if not isinstance(leader_result, gl.vm.Return):
            return False
        try:
            _validate_signed_envelope(leader_result.calldata, context_binding, sys_model)
            return True
        except Exception:
            return False

    approved_envelope = gl.vm.run_nondet_unsafe(leader_propose, validator_check)
    _validate_signed_envelope(approved_envelope, context_binding, sys_model)
    return approved_envelope


def _halt(reason: str) -> None:
    raise gl.vm.UserError("[BARRIER_HALT] " + reason)


class PolytopeBarrierVerifier(gl.Contract):
    systems: TreeMap[str, str]
    certificates: TreeMap[str, str]
    trial_counts: TreeMap[str, u256]
    author_quotas: TreeMap[str, u256]

    def __init__(self):
        pass

    @gl.public.write
    def publish_system(self, tag_nonce: str, system_json: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", tag_nonce):
            _halt("Malformed tag nonce")
        try:
            parsed_system = _parse_dynamical_system(system_json)
        except Exception:
            _halt("Invalid dynamical system specification")

        caller = str(gl.message.sender_address)
        self_addr = str(gl.message.contract_address)
        system_id = _sha256_digest({"contract": self_addr, "author": caller, "nonce": tag_nonce})

        if system_id in self.systems:
            _halt("System nonce already registered")

        used_quota = int(self.author_quotas.get(caller, 0))
        if used_quota >= MAX_AUTHOR_SYSTEMS:
            _halt("Author registration quota exceeded")

        entry = {
            "protocol": PROTOCOL_VERSION,
            "contract": self_addr,
            "author": caller,
            "nonce": tag_nonce,
            "model": parsed_system,
            "model_hash": _sha256_digest(parsed_system),
        }
        entry["state_root"] = _sha256_digest(entry)

        self.systems[system_id] = _canonical_json(entry)
        self.author_quotas[caller] = used_quota + 1
        return system_id

    @gl.public.write
    def generate_certificate(self, system_id: str, expected_trial: int) -> str:
        stored_sys = self.get_system(system_id)
        current_trial = int(self.trial_counts.get(system_id, 0))

        if type(expected_trial) is not int or expected_trial != current_trial:
            _halt("Trial sequence mismatch")
        if current_trial >= MAX_SYNTHESIS_TRIALS:
            _halt("Maximum synthesis trials reached")

        context_binding = {
            "protocol": PROTOCOL_VERSION,
            "contract": str(gl.message.contract_address),
            "system_id": system_id,
            "system_root": stored_sys["state_root"],
            "model_hash": stored_sys["model_hash"],
            "caller": str(gl.message.sender_address),
            "trial": current_trial,
        }

        try:
            verified_envelope = _run_consensus_synthesis(context_binding, stored_sys["model"])
        except Exception:
            _halt("Consensus synthesis failed to produce a verified barrier")

        cert_id = _sha256_digest({"system_id": system_id, "trial": current_trial})
        cert_record = {"status": "VERIFIED", "envelope": verified_envelope}
        cert_record["cert_root"] = _sha256_digest(cert_record)

        self.certificates[cert_id] = _canonical_json(cert_record)
        self.trial_counts[system_id] = current_trial + 1
        return cert_id

    @gl.public.view
    def get_system(self, system_id: str) -> dict:
        if system_id not in self.systems:
            _halt("System ID not found")
        return json.loads(self.systems[system_id])

    @gl.public.view
    def get_certificate(self, cert_id: str) -> dict:
        if cert_id not in self.certificates:
            _halt("Certificate ID not found")
        return json.loads(self.certificates[cert_id])

    @gl.public.view
    def get_trial_count(self, system_id: str) -> int:
        self.get_system(system_id)
        return int(self.trial_counts.get(system_id, 0))

    @gl.public.view
    def verify_certificate_offline(self, system_id: str, candidate_cert_json: str) -> bool:
        sys_model = self.get_system(system_id)["model"]
        try:
            _verify_barrier_certificate(sys_model, candidate_cert_json)
            return True
        except Exception:
            return False

    @gl.public.view
    def export_verified_claim(
        self,
        cert_id: str,
        expected_system_root: str,
        expected_cert_root: str,
    ) -> dict:
        cert_record = self.get_certificate(cert_id)
        binding = cert_record["envelope"]["binding"]
        stored_sys = self.get_system(binding["system_id"])

        if expected_system_root != stored_sys["state_root"] or expected_cert_root != cert_record["cert_root"]:
            _halt("Cryptographic root commitment mismatch")

        try:
            _verify_barrier_certificate(stored_sys["model"], cert_record["envelope"]["proof"])
        except Exception:
            _halt("Stored certificate failed re-verification")

        return {
            "system_root": stored_sys["state_root"],
            "cert_root": cert_record["cert_root"],
            "model_hash": stored_sys["model_hash"],
            "barrier_invariant": cert_record["envelope"]["proof"]["invariant"],
            "safety_polytope": stored_sys["model"]["safety"],
            "domain_semantics": "exact-integer-linear-arithmetic",
        }