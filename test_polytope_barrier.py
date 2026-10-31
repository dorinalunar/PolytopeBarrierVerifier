import json
from pathlib import Path
import sys
import types
import pytest


def _install_genlayer_mock():
    if "genlayer" in sys.modules:
        return

    mock_gl = types.ModuleType("genlayer")

    class _UserError(Exception):
        pass

    class _Return:
        def __init__(self, calldata):
            self.calldata = calldata

    class _VM:
        UserError = _UserError
        Return = _Return

        @staticmethod
        def run_nondet_unsafe(leader_fn, validator_fn):
            result = leader_fn()
            wrapped = _Return(result)
            if not validator_fn(wrapped):
                raise _UserError("Validator rejected leader result")
            return result

    class _Nondet:
        _mock_response = None

        @classmethod
        def exec_prompt(cls, prompt_text: str, response_format: str = "json"):
            if callable(cls._mock_response):
                return cls._mock_response(prompt_text)
            if cls._mock_response is not None:
                return cls._mock_response
            raise _UserError("No mock LLM response configured")

    class _PublicProxy:
        def write(self, fn):
            return fn

        def view(self, fn):
            return fn

    class _Message:
        sender_address = "0x38409cCa5f5ca70F3fe189638a87862318b478dd"
        contract_address = "0xDA60bEe633fA82B9497559A97D7E07997C3B4c22"

    class _Contract:
        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            orig_init = cls.__init__

            def _wrapped_init(self, *args, **kw):
                for attr in getattr(cls, "__annotations__", {}):
                    setattr(self, attr, {})
                orig_init(self, *args, **kw)

            cls.__init__ = _wrapped_init

    class _TreeMapMeta(type):
        def __getitem__(cls, item):
            return dict

    class TreeMap(dict, metaclass=_TreeMapMeta):
        pass

    mock_gl.vm = _VM
    mock_gl.nondet = _Nondet
    mock_gl.public = _PublicProxy()
    mock_gl.message = _Message
    mock_gl.Contract = _Contract
    mock_gl.TreeMap = TreeMap
    mock_gl.u256 = int
    mock_gl.gl = mock_gl
    mock_gl.__all__ = ["gl", "TreeMap", "u256"]

    sys.modules["genlayer"] = mock_gl


_install_genlayer_mock()

import genlayer as gl_mod  # noqa: E402
from PolytopeBarrierVerifier import (  # noqa: E402
    PolytopeBarrierVerifier,
    _parse_dynamical_system,
    _verify_barrier_certificate,
)


def sample_1d_counter_system() -> dict:
    return {
        "dimension": 1,
        "initial": [{"a": [1], "b": 0}, {"a": [-1], "b": 0}],
        "guard": [{"a": [1], "b": 9}],
        "matrix": [[1]],
        "offset": [1],
        "safety": [{"a": [1], "b": 10}],
        "seed": [0],
    }


def sample_1d_valid_certificate() -> dict:
    return {
        "invariant": [{"a": [1], "b": 10}],
        "initial": [{"weights": [1, 0], "scale": 1}],
        "step": [{"weights": [0, 1], "scale": 1}],
        "safety": [{"weights": [1], "scale": 1}],
    }


def sample_2d_coupled_system() -> dict:
    return {
        "dimension": 2,
        "initial": [
            {"a": [1, 0], "b": 0},
            {"a": [0, 1], "b": 0},
            {"a": [-1, 0], "b": 0},
            {"a": [0, -1], "b": 0},
        ],
        "guard": [{"a": [1, 1], "b": 8}],
        "matrix": [[1, 0], [0, 1]],
        "offset": [1, 1],
        "safety": [{"a": [1, 1], "b": 10}],
        "seed": [0, 0],
    }


def sample_2d_valid_certificate() -> dict:
    return {
        "invariant": [{"a": [1, 1], "b": 10}],
        "initial": [{"weights": [1, 1, 0, 0], "scale": 1}],
        "step": [{"weights": [0, 1], "scale": 1}],
        "safety": [{"weights": [1], "scale": 1}],
    }


def test_parse_valid_1d_and_2d_systems():
    s1 = _parse_dynamical_system(json.dumps(sample_1d_counter_system()))
    assert s1["dimension"] == 1
    s2 = _parse_dynamical_system(json.dumps(sample_2d_coupled_system()))
    assert s2["dimension"] == 2


def test_reject_duplicate_json_keys():
    raw_dup = '{"dimension":1,"dimension":1,"initial":[{"a":[1],"b":0}],"guard":[{"a":[1],"b":9}],"matrix":[[1]],"offset":[1],"safety":[{"a":[1],"b":10}],"seed":[0]}'
    with pytest.raises(ValueError, match="Duplicate key"):
        _parse_dynamical_system(raw_dup)


def test_reject_seed_outside_initial_polytope():
    bad_sys = sample_1d_counter_system()
    bad_sys["seed"] = [5]
    with pytest.raises(ValueError, match="Anchor seed violates initial polytope"):
        _parse_dynamical_system(json.dumps(bad_sys))


def test_verify_valid_1d_and_2d_certificates():
    s1 = sample_1d_counter_system()
    c1 = sample_1d_valid_certificate()
    verified_1d = _verify_barrier_certificate(s1, c1)
    assert verified_1d["invariant"][0]["b"] == 10

    s2 = sample_2d_coupled_system()
    c2 = sample_2d_valid_certificate()
    verified_2d = _verify_barrier_certificate(s2, c2)
    assert verified_2d["invariant"][0]["a"] == [1, 1]


def test_reject_invalid_farkas_normal_combination():
    s1 = sample_1d_counter_system()
    bad_cert = sample_1d_valid_certificate()
    bad_cert["initial"][0]["weights"] = [2, 0]
    with pytest.raises(ValueError, match="Normal vector conic combination mismatch"):
        _verify_barrier_certificate(s1, bad_cert)


def test_reject_violated_halfspace_bound():
    s1 = sample_1d_counter_system()
    bad_cert = sample_1d_valid_certificate()
    bad_cert["step"][0]["weights"] = [1, 0]
    with pytest.raises(ValueError, match="Halfspace offset implication violated"):
        _verify_barrier_certificate(s1, bad_cert)


def test_contract_publish_and_offline_verification():
    contract = PolytopeBarrierVerifier()
    sys_json = json.dumps(sample_1d_counter_system())
    sys_id = contract.publish_system("counter_loop_v1", sys_json)

    stored = contract.get_system(sys_id)
    assert stored["nonce"] == "counter_loop_v1"
    assert contract.get_trial_count(sys_id) == 0

    valid_cert_json = json.dumps(sample_1d_valid_certificate())
    assert contract.verify_certificate_offline(sys_id, valid_cert_json) is True

    tampered = sample_1d_valid_certificate()
    tampered["safety"][0]["weights"] = [0]
    assert contract.verify_certificate_offline(sys_id, json.dumps(tampered)) is False


def test_contract_consensus_synthesis_and_claim_export():
    contract = PolytopeBarrierVerifier()
    sys_id = contract.publish_system("coupled_2d_v1", json.dumps(sample_2d_coupled_system()))

    gl_mod.gl.nondet._mock_response = sample_2d_valid_certificate()
    cert_id = contract.generate_certificate(sys_id, 0)

    assert contract.get_trial_count(sys_id) == 1
    sys_record = contract.get_system(sys_id)
    cert_record = contract.get_certificate(cert_id)

    claim = contract.export_verified_claim(
        cert_id,
        sys_record["state_root"],
        cert_record["cert_root"],
    )
    assert claim["domain_semantics"] == "exact-integer-linear-arithmetic"
    assert claim["barrier_invariant"] == [{"a": [1, 1], "b": 10}]


def test_contract_enforces_trial_sequence_and_duplicate_nonce():
    contract = PolytopeBarrierVerifier()
    sys_id = contract.publish_system("unique_nonce_01", json.dumps(sample_1d_counter_system()))

    with pytest.raises(gl_mod.gl.vm.UserError, match="System nonce already registered"):
        contract.publish_system("unique_nonce_01", json.dumps(sample_1d_counter_system()))

    with pytest.raises(gl_mod.gl.vm.UserError, match="Trial sequence mismatch"):
        contract.generate_certificate(sys_id, 5)


def test_sample_dataset_json_end_to_end():
    dataset_path = Path(__file__).parent / "sample_dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    assert dataset["dataset_version"] == "polytope-barrier-verifier-v1"
    assert len(dataset["samples"]) >= 3

    contract = PolytopeBarrierVerifier()
    for item in dataset["samples"]:
        sys_id = contract.publish_system(item["nonce"], json.dumps(item["system"]))
        assert contract.verify_certificate_offline(sys_id, json.dumps(item["valid_certificate"])) is True
