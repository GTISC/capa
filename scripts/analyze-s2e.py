#!/usr/bin/env python3
"""Match capa dynamic rules against a Mal-S2E API lifecycle journal."""

import argparse
import json
import re
from pathlib import Path

import capa.rules
from capa.capabilities.dynamic import find_dynamic_capabilities
from capa.features.extractors.s2e import S2ELifecycleExtractor

ATTACK_ID = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="S2E output directory or api-lifecycle.jsonl")
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--architecture", choices=("i386", "x86_64", "amd64"), default="i386")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    extractor = S2ELifecycleExtractor(args.output, args.architecture)
    rules = capa.rules.get_rules([args.rules], enable_cache=False)
    capabilities = find_dynamic_capabilities(rules, extractor, disable_progress=True)
    matches = []
    attack_ids = set()
    for name, results in sorted(capabilities.matches.items()):
        rule = rules[name]
        ids = sorted(
            {
                match.group(1)
                for value in rule.meta.get("att&ck", [])
                if (match := ATTACK_ID.search(str(value))) is not None
            }
        )
        if not ids:
            continue
        attack_ids.update(ids)
        matches.append(
            {
                "rule": name,
                "attack_ids": ids,
                "dynamic_scope": rule.scopes.dynamic.value,
                "locations": sorted({repr(address) for address, _ in results}),
            }
        )
    result = {
        "schema": 1,
        "scope": (
            "capa dynamic-rule candidates from paired successful S2E API returns; "
            "matches do not establish ATT&CK technique completion or adversary intent"
        ),
        "input": str(extractor.output.resolve()),
        "architecture": args.architecture,
        "successful_state_streams": len(extractor.streams),
        "successful_calls": sum(len(stream.calls) for stream in extractor.streams),
        "candidate_attack_ids": sorted(attack_ids),
        "matches": matches,
    }
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(serialized)
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
