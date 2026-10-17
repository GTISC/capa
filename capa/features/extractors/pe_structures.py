# Copyright 2026 GTISC
# Licensed under the Apache License, Version 2.0.
"""Bounded structural PE observations, independent of names or ATT&CK tags."""

import pefile

from capa.features.address import FileOffsetAddress
from capa.features.common import Characteristic


def valid_pe(buf, available_length):
    try:
        pe = pefile.PE(data=buf, fast_load=True)
    except (pefile.PEFormatError, ValueError, OverflowError):
        return None
    if (
        not pe.sections
        or len(pe.sections) > 96
        or len(pe.sections) != pe.FILE_HEADER.NumberOfSections
        or pe.OPTIONAL_HEADER.Magic not in {0x10B, 0x20B}
        or not pe.FILE_HEADER.Characteristics & 2
        or pe.OPTIONAL_HEADER.SizeOfHeaders > available_length
        or not any(section.SizeOfRawData for section in pe.sections)
        or any(
            section.PointerToRawData + section.SizeOfRawData > available_length
            for section in pe.sections
        )
    ):
        pe.close()
        return None
    return pe


def extract_features(buf):
    # Literal, fully bounded nested PE variant. XOR/encrypted/carved fragments
    # are intentionally not accepted merely because two magic bytes match.
    offset = 1
    for _ in range(256):
        offset = buf.find(b"MZ", offset)
        if offset < 0:
            break
        nested = valid_pe(buf[offset : offset + 65536], len(buf) - offset)
        if nested is not None:
            yield (
                Characteristic("embedded pe with valid sections"),
                FileOffsetAddress(offset),
            )
            nested.close()
        offset += 2

    pe = valid_pe(buf[:65536], len(buf))
    if pe is None:
        return
    try:
        start = max(
            pe.OPTIONAL_HEADER.SizeOfHeaders,
            *(s.PointerToRawData + s.SizeOfRawData for s in pe.sections),
        )
        if start >= len(buf):
            return
        spans = [(start, len(buf))]
        security = (
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4
            else None
        )
        cert_start = security.VirtualAddress if security else 0
        cert_end = cert_start + security.Size if security else 0
        if security and security.Size and cert_start < len(buf) and cert_end > start:
            spans = [
                (start, min(len(buf), cert_start)),
                (max(start, cert_end), len(buf)),
            ]
        for begin, end in spans:
            length = end - begin
            if length < 65536 or length * 4 < len(buf):
                continue
            fill = buf[begin]
            if fill in {0, 255} and buf.count(bytes([fill]), begin, end) == length:
                yield (
                    Characteristic("large uniform pe overlay"),
                    FileOffsetAddress(begin),
                )
    finally:
        pe.close()
