"""Discover and validate classic Turbo Pascal overlay descriptors.

For ``TPOV`` images, the directory is resident in the associated MZ load
module rather than stored as a conventional table in the overlay file.  Each
descriptor is accepted only when its procedure stubs are structurally valid,
and the final directory must form one unique, gap-free chain across every byte
after the overlay signature.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from pathlib import Path

from binary_comp.core.mz import MzImage, parse_mz


TPOV_SIGNATURE = b"TPOV"
DESCRIPTOR_SIZE = 32
PROCEDURE_STUB_SIZE = 5
TRAP = b"\xCD\x3F"


class TpOverlayError(RuntimeError):
    """Raised when a resident overlay directory is absent or inconsistent."""


@dataclass(frozen=True)
class TpOverlayDescriptor:
    index: int
    image_offset: int
    executable_offset: int
    file_offset: int
    code_size: int
    fixup_size: int
    procedure_count: int
    unit_number: int

    @property
    def code_end(self) -> int:
        return self.file_offset + self.code_size

    @property
    def extent_end(self) -> int:
        return self.code_end + self.fixup_size


@dataclass(frozen=True)
class TpOverlayImage:
    mz: MzImage
    signature: bytes
    file_size: int
    descriptors: tuple[TpOverlayDescriptor, ...]


def _descriptor_candidates(
    mz: MzImage, overlay: bytes, signature_size: int
) -> tuple[TpOverlayDescriptor, ...]:
    image = mz.load_module
    candidates: list[TpOverlayDescriptor] = []
    for image_offset in range(0, max(0, len(image) - DESCRIPTOR_SIZE + 1)):
        if image[image_offset:image_offset + 4] != TRAP + b"\x00\x00":
            continue
        (
            _marker,
            _reserved,
            file_offset,
            code_size,
            fixup_size,
            procedure_count,
            unit_number,
        ) = struct.unpack_from("<HHIHHHH", image, image_offset)
        extent_end = file_offset + code_size + fixup_size
        if (
            file_offset < signature_size
            or extent_end <= file_offset
            or extent_end > len(overlay)
            or procedure_count > 0x1000
        ):
            continue

        stub_start = image_offset + DESCRIPTOR_SIZE
        stub_end = stub_start + procedure_count * PROCEDURE_STUB_SIZE
        if stub_end > len(image):
            continue
        if any(
            image[
                stub_start + index * PROCEDURE_STUB_SIZE:
                stub_start + index * PROCEDURE_STUB_SIZE + len(TRAP)
            ] != TRAP
            for index in range(procedure_count)
        ):
            continue

        candidates.append(TpOverlayDescriptor(
            index=0,
            image_offset=image_offset,
            executable_offset=mz.header.header_size + image_offset,
            file_offset=file_offset,
            code_size=code_size,
            fixup_size=fixup_size,
            procedure_count=procedure_count,
            unit_number=unit_number,
        ))
    return tuple(candidates)


def parse_tp_overlay(executable: bytes, overlay: bytes) -> TpOverlayImage:
    """Recover a unique resident directory and validate complete TPOV coverage."""

    try:
        mz = parse_mz(executable)
    except RuntimeError as exc:
        raise TpOverlayError(str(exc)) from exc
    if not overlay.startswith(TPOV_SIGNATURE):
        raise TpOverlayError(
            f"expected {TPOV_SIGNATURE!r} signature, found {overlay[:4]!r}"
        )

    signature_size = len(TPOV_SIGNATURE)
    by_file_offset: dict[int, list[TpOverlayDescriptor]] = {}
    for candidate in _descriptor_candidates(mz, overlay, signature_size):
        by_file_offset.setdefault(candidate.file_offset, []).append(candidate)

    directory: list[TpOverlayDescriptor] = []
    next_file_offset = signature_size
    while next_file_offset < len(overlay):
        matches = by_file_offset.get(next_file_offset, [])
        if len(matches) != 1:
            raise TpOverlayError(
                f"expected one descriptor for overlay offset "
                f"0x{next_file_offset:X}, found {len(matches)}"
            )
        item = replace(matches[0], index=len(directory) + 1)
        directory.append(item)
        next_file_offset = item.extent_end

    if next_file_offset != len(overlay):
        raise TpOverlayError(
            f"overlay chain ends at 0x{next_file_offset:X}; "
            f"file ends at 0x{len(overlay):X}"
        )
    if not directory:
        raise TpOverlayError("overlay contains no descriptor-backed units")
    return TpOverlayImage(
        mz=mz,
        signature=TPOV_SIGNATURE,
        file_size=len(overlay),
        descriptors=tuple(directory),
    )


def load_tp_overlay(
    executable_path: str | Path, overlay_path: str | Path
) -> TpOverlayImage:
    return parse_tp_overlay(
        Path(executable_path).read_bytes(), Path(overlay_path).read_bytes()
    )


def format_tp_overlay(image: TpOverlayImage) -> str:
    mz = image.mz.header
    lines = [
        "DOS MZ image",
        f"  declared size:    {mz.declared_size} (0x{mz.declared_size:X})",
        f"  header size:      {mz.header_size} (0x{mz.header_size:X})",
        f"  load module:      {mz.load_module_size} bytes",
        f"  relocations:      {mz.relocation_count} @ 0x{mz.relocation_offset:X}",
        f"  entry CS:IP:      {mz.cs:04X}:{mz.ip:04X}",
        f"  initial SS:SP:    {mz.ss:04X}:{mz.sp:04X}",
        "",
        "Turbo Pascal overlay image",
        f"  signature:        {image.signature.decode('ascii')}",
        f"  file size:        {image.file_size} (0x{image.file_size:X})",
        f"  overlay entries:  {len(image.descriptors)}",
        "",
        "OVR     EXE desc  FileOfs  CodeSize  Fixups  Procs  TP unit",
    ]
    for item in image.descriptors:
        lines.append(
            f"ovr{item.index:03d}  0x{item.executable_offset:06X}  "
            f"0x{item.file_offset:06X}  0x{item.code_size:06X}  "
            f"0x{item.fixup_size:04X}  {item.procedure_count:5d}  "
            f"{item.unit_number:7d}"
        )
    lines.extend((
        "",
        f"validated: descriptors cover overlay[0x{len(image.signature):X}:"
        f"0x{image.file_size:X}] exactly",
    ))
    return "\n".join(lines)
