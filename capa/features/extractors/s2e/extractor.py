# Copyright 2026 GTISC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dynamic feature extractor for Mal-S2E's validated API lifecycle journal.

S2E execution states are independent paths. Each ``(instance, pid, lifetime,
state)`` tuple is therefore exposed as a separate capa process so that rule
matching never combines calls from divergent symbolic states.

Only calls with a paired, successful return become capa call features. This
is deliberately stricter than most sandbox extractors: an API entry or failed
call is useful reachability evidence, but it is not successful runtime
behavior.
"""

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import capa.features.extractors.helpers
from capa.features.address import (
    NO_ADDRESS,
    Address,
    DynamicCallAddress,
    ProcessAddress,
    ThreadAddress,
)
from capa.features.common import (
    ARCH_AMD64,
    ARCH_I386,
    FORMAT_PE,
    OS,
    OS_WINDOWS,
    Arch,
    Feature,
    Format,
    String,
)
from capa.features.extractors.base_extractor import (
    CallHandle,
    DynamicFeatureExtractor,
    ProcessHandle,
    SampleHashes,
    ThreadHandle,
)
from capa.features.insn import API, Number

API_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_@?$-]{0,255}")
ARCHES = {"i386": ARCH_I386, "x86_64": ARCH_AMD64, "amd64": ARCH_AMD64}
INTEGER_ARGUMENTS = (
    "requested",
    "input_capacity",
    "mapping_size",
    "credential_flags",
)
STRING_ARGUMENTS = ("path_hex", "value_hex", "mapping_name_hex")


@dataclass(frozen=True)
class S2ECall:
    row: dict


@dataclass(frozen=True)
class S2EStream:
    instance: int
    pid: int
    lifetime: int
    state: int
    calls: tuple[S2ECall, ...]


def _sample_hashes(output: Path) -> SampleHashes:
    sha256 = "0" * 64
    basis = output / "address_basis.json"
    if basis.is_file():
        value = json.loads(basis.read_text()).get("observed_sha256")
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
            sha256 = value.lower()
    return SampleHashes(md5="0" * 32, sha1="0" * 40, sha256=sha256)


def _decode_text(value: str) -> str | None:
    raw = bytes.fromhex(value)
    if not raw:
        return None
    encodings = ("utf-16le", "utf-8") if len(raw) >= 2 and raw[1::2].count(0) * 2 >= len(raw) // 2 else ("utf-8", "utf-16le")
    for encoding in encodings:
        try:
            text = raw.decode(encoding).rstrip("\x00")
        except UnicodeDecodeError:
            continue
        if text and all(character.isprintable() or character in "\r\n\t" for character in text):
            return text
    return None


def _validate_arguments(row: dict, line_number: int) -> None:
    """Validate optional, explicitly named concrete lifecycle arguments."""
    if "arguments" not in row:
        return
    arguments = row["arguments"]
    if not isinstance(arguments, list):
        # Treat all untrusted journal-shape failures uniformly for callers.
        raise ValueError(  # noqa: TRY004
            f"invalid lifecycle arguments on line {line_number}"
        )
    for argument in arguments:
        if (
            not isinstance(argument, dict)
            or not isinstance(argument.get("name"), str)
            or not argument["name"]
            or type(argument.get("value")) not in {str, int}
        ):
            raise ValueError(f"invalid lifecycle argument on line {line_number}")


def _load_streams(output: Path) -> tuple[S2EStream, ...]:
    journal = output / "api-lifecycle.jsonl"
    if not journal.is_file():
        raise ValueError(f"missing S2E API lifecycle journal: {journal}")

    entries: dict[tuple[int, int], dict] = {}
    completed: dict[tuple[int, int, int, int], list[S2ECall]] = {}
    for line_number, line in enumerate(journal.read_text().splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid lifecycle JSON on line {line_number}") from error
        event = row.get("event")
        if row.get("schema") != 1 or event not in {"enter", "return"}:
            raise ValueError(f"invalid lifecycle schema or event on line {line_number}")
        if API_NAME.fullmatch(str(row.get("api", ""))) is None:
            raise ValueError(f"invalid lifecycle API on line {line_number}")
        for key in (
            "instance",
            "state",
            "time_ns",
            "entry_time_ns",
            "pid",
            "lifetime",
            "depth",
            "call_id",
            "caller_pc",
            "callee_pc",
            "requested",
            "input_capacity",
        ):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError(f"invalid lifecycle {key} on line {line_number}")
        if not row["pid"] or not row["call_id"] or row.get("diagnostic_lineage") is not False:
            raise ValueError(f"unattributed lifecycle call on line {line_number}")
        for key in ("module_hex", "path_hex", "value_hex"):
            try:
                bytes.fromhex(row[key])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"invalid lifecycle {key} on line {line_number}") from error
        _validate_arguments(row, line_number)

        identity = (row["instance"], row["call_id"])
        if event == "enter":
            if identity in entries:
                raise ValueError(f"duplicate lifecycle entry on line {line_number}")
            entries[identity] = row
            continue

        entry = entries.get(identity)
        if entry is None or any(row.get(key) != entry.get(key) for key in ("pid", "lifetime", "api")):
            raise ValueError(f"lifecycle return lacks matching entry on line {line_number}")
        if (
            type(row.get("success")) is not bool
            or type(row.get("result")) is not int
            or row["result"] < 0
            or type(row.get("elapsed_ns")) is not int
            or row["elapsed_ns"] < 0
            or row["entry_time_ns"] != entry["entry_time_ns"]
            or row["time_ns"] < entry["time_ns"]
        ):
            raise ValueError(f"invalid lifecycle success on line {line_number}")
        if not row["success"]:
            continue
        stream = (row["instance"], row["pid"], row["lifetime"], row["state"])
        completed.setdefault(stream, []).append(S2ECall(row=row))

    result = []
    for key, calls in sorted(completed.items()):
        calls.sort(key=lambda call: (call.row["time_ns"], call.row["call_id"]))
        result.append(S2EStream(*key, calls=tuple(calls)))
    return tuple(result)


class S2ELifecycleExtractor(DynamicFeatureExtractor):
    """Expose successful Mal-S2E API calls to capa's dynamic rule engine."""

    def __init__(self, output: Path, architecture: str = "i386"):
        output = Path(output)
        if output.is_file():
            if output.name != "api-lifecycle.jsonl":
                raise ValueError("S2E input file must be named api-lifecycle.jsonl")
            output = output.parent
        if architecture not in ARCHES:
            raise ValueError(f"unsupported S2E architecture: {architecture}")
        super().__init__(_sample_hashes(output))
        self.output = output
        self.architecture = architecture
        self.streams = _load_streams(output)
        self._processes = {
            ProcessAddress(index): stream for index, stream in enumerate(self.streams, 1)
        }

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        yield OS(OS_WINDOWS), NO_ADDRESS
        yield Format(FORMAT_PE), NO_ADDRESS
        yield Arch(ARCHES[self.architecture]), NO_ADDRESS

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from ()

    def get_processes(self) -> Iterator[ProcessHandle]:
        for address, stream in self._processes.items():
            yield ProcessHandle(address=address, inner=stream)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
        yield from ()

    def get_process_name(self, ph: ProcessHandle) -> str:
        stream: S2EStream = ph.inner
        return f"s2e:{stream.instance}:{stream.pid}:{stream.lifetime}:state-{stream.state}"

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        yield ThreadHandle(address=ThreadAddress(ph.address, 0), inner=ph.inner)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[tuple[Feature, Address]]:
        yield from ()

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        stream: S2EStream = th.inner
        for call in stream.calls:
            address = DynamicCallAddress(th.address, call.row["call_id"])
            yield CallHandle(address=address, inner=call)

    def extract_call_features(
        self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        call: S2ECall = ch.inner
        row = call.row
        for symbol in capa.features.extractors.helpers.generate_symbols("", row["api"]):
            yield API(symbol), ch.address
        for key in STRING_ARGUMENTS:
            value = row.get(key)
            if not isinstance(value, str):
                continue
            text = _decode_text(value)
            if text is not None:
                yield String(text), ch.address
        for key in INTEGER_ARGUMENTS:
            value = row.get(key)
            # S2E uses zero as the placeholder when this generic field does
            # not apply. Emitting it for every call creates false matches.
            if type(value) is int and value > 0:
                yield Number(value), ch.address
        # Generic named arguments are emitted only when the lifecycle producer
        # explicitly records a concrete value. Unlike legacy generic fields,
        # zero is meaningful here (for example, a NULL local-server argument).
        for argument in row.get("arguments", []):
            value = argument["value"]
            if type(value) is str:
                yield String(value), ch.address
            else:
                yield Number(value), ch.address

    def get_call_name(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> str:
        call: S2ECall = ch.inner
        return f"{call.row['api']}() -> {call.row.get('result_hex', call.row.get('result'))}"
