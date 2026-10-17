import json

import capa.rules
from capa.capabilities.dynamic import find_dynamic_capabilities
from capa.features.common import String
from capa.features.extractors.s2e import S2ELifecycleExtractor
from capa.features.insn import API, Number


def lifecycle(event, call_id, api, *, state=0, success=True, path=b"", arguments=None):
    row = {
        "schema": 1,
        "instance": 0,
        "state": state,
        "time_ns": call_id * 10 + (event == "return"),
        "entry_time_ns": call_id * 10,
        "pid": 100,
        "lifetime": 0,
        "depth": 0,
        "diagnostic_lineage": False,
        "call_id": call_id,
        "event": event,
        "api": api,
        "module_hex": b"advapi32.dll".hex(),
        "caller_pc": 0x401000,
        "callee_pc": 0x77001000,
        "path_hex": path.hex(),
        "value_hex": "",
        "requested": 0,
        "input_capacity": 0,
    }
    if event == "return":
        row.update(
            result=1 if success else 0,
            result_hex="0x1" if success else "0x0",
            success=success,
            elapsed_ns=1,
        )
    if arguments is not None:
        row["arguments"] = arguments
    return row


def save(tmp_path, rows):
    (tmp_path / "api-lifecycle.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_extracts_only_paired_successful_calls_and_concrete_arguments(tmp_path):
    save(
        tmp_path,
        [
            lifecycle("enter", 1, "RegOpenKeyExW", path=rb"HKCU\Software\Probe"),
            lifecycle("return", 1, "RegOpenKeyExW", path=rb"HKCU\Software\Probe"),
            lifecycle("enter", 2, "DeleteFileW", path=rb"C:\missing"),
            lifecycle("return", 2, "DeleteFileW", success=False, path=rb"C:\missing"),
        ],
    )
    extractor = S2ELifecycleExtractor(tmp_path)
    process = next(extractor.get_processes())
    thread = next(extractor.get_threads(process))
    calls = list(extractor.get_calls(process, thread))
    assert len(calls) == 1
    features = {feature for feature, _ in extractor.extract_call_features(process, thread, calls[0])}
    assert API("RegOpenKeyExW") in features
    assert API("RegOpenKeyEx") in features
    assert String(r"HKCU\Software\Probe") in features
    assert API("DeleteFileW") not in features


def test_never_combines_calls_from_divergent_s2e_states(tmp_path):
    rows = [
        lifecycle("enter", 1, "RegOpenKeyExW", state=1),
        lifecycle("return", 1, "RegOpenKeyExW", state=1),
        lifecycle("enter", 2, "RegQueryValueExW", state=2),
        lifecycle("return", 2, "RegQueryValueExW", state=2),
    ]
    save(tmp_path, rows)
    rule = capa.rules.Rule.from_yaml(
        """
rule:
  meta:
    name: test S2E state isolation
    namespace: test
    authors: [test]
    scopes:
      static: unsupported
      dynamic: span of calls
  features:
    - and:
      - api: RegOpenKeyEx
      - api: RegQueryValueEx
"""
    )
    capabilities = find_dynamic_capabilities(
        capa.rules.RuleSet([rule]), S2ELifecycleExtractor(tmp_path), disable_progress=True
    )
    assert "test S2E state isolation" not in capabilities.matches


def test_matches_successful_calls_within_one_state(tmp_path):
    rows = [
        lifecycle("enter", 1, "RegOpenKeyExW", state=1),
        lifecycle("return", 1, "RegOpenKeyExW", state=1),
        lifecycle("enter", 2, "RegQueryValueExW", state=1),
        lifecycle("return", 2, "RegQueryValueExW", state=1),
    ]
    save(tmp_path, rows)
    rule = capa.rules.Rule.from_yaml(
        """
rule:
  meta:
    name: test S2E successful calls
    namespace: test
    authors: [test]
    scopes:
      static: unsupported
      dynamic: span of calls
  features:
    - and:
      - api: RegOpenKeyEx
      - api: RegQueryValueEx
"""
    )
    capabilities = find_dynamic_capabilities(
        capa.rules.RuleSet([rule]), S2ELifecycleExtractor(tmp_path), disable_progress=True
    )
    assert "test S2E successful calls" in capabilities.matches


def test_extracts_explicit_concrete_string_and_zero_arguments(tmp_path):
    arguments = [
        {"name": "servername", "value": "localhost"},
        {"name": "scope", "value": 0},
    ]
    save(
        tmp_path,
        [
            lifecycle("enter", 1, "NetShareEnum", arguments=arguments),
            lifecycle("return", 1, "NetShareEnum", arguments=arguments),
        ],
    )
    extractor = S2ELifecycleExtractor(tmp_path)
    process = next(extractor.get_processes())
    thread = next(extractor.get_threads(process))
    call = next(extractor.get_calls(process, thread))
    features = {feature for feature, _ in extractor.extract_call_features(process, thread, call)}
    assert String("localhost") in features
    assert Number(0) in features


def test_rejects_symbolic_or_malformed_explicit_arguments(tmp_path):
    rows = [
        lifecycle("enter", 1, "NetShareEnum"),
        lifecycle(
            "return",
            1,
            "NetShareEnum",
            arguments=[{"name": "servername", "value": {"symbolic": True}}],
        ),
    ]
    save(tmp_path, rows)
    try:
        S2ELifecycleExtractor(tmp_path)
    except ValueError as error:
        assert "invalid lifecycle argument" in str(error)
    else:
        raise AssertionError("symbolic lifecycle argument was accepted")
