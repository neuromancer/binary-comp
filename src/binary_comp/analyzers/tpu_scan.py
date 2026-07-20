"""Locate relocation-masked Turbo Pascal code blocks in DOS target images."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from binary_comp.analyzers.tp_overlay import TpOverlayDescriptor, parse_tp_overlay
from binary_comp.analyzers.tpu import build_mask, load_tpu_object, locate_code_window


@dataclass(frozen=True)
class TpuBlockLocation:
    image: str
    file_offset: int
    image_offset: int
    overlay_index: int | None = None


@dataclass(frozen=True)
class TpuBlockMatch:
    unit: str
    procedure: str
    block_index: int
    size: int
    fixed_bytes: int
    locations: tuple[TpuBlockLocation, ...]

    @property
    def is_unique(self) -> bool:
        return len(self.locations) == 1


@dataclass(frozen=True)
class TpuScanResult:
    overlay_count: int
    matches: tuple[TpuBlockMatch, ...]

    @property
    def unique_count(self) -> int:
        return sum(match.is_unique for match in self.matches)

    @property
    def ambiguous_count(self) -> int:
        return sum(not match.is_unique for match in self.matches)


def _containing_descriptor(
    offset: int,
    size: int,
    descriptors: tuple[TpOverlayDescriptor, ...],
) -> TpOverlayDescriptor | None:
    for descriptor in descriptors:
        if descriptor.file_offset <= offset and offset + size <= descriptor.code_end:
            return descriptor
    return None


def scan_tpu_blocks(
    executable: bytes,
    overlay: bytes,
    tpu_paths: list[str | Path] | tuple[str | Path, ...],
    *,
    minimum_block_size: int = 8,
    minimum_fixed_bytes: int = 8,
    function_filter: str | None = None,
) -> TpuScanResult:
    """Find compiled-unit code blocks in resident and descriptor-bounded code."""

    if minimum_block_size < 1 or minimum_fixed_bytes < 1:
        raise ValueError("minimum block and fixed-byte sizes must be positive")
    target = parse_tp_overlay(executable, overlay)
    resident = target.mz.load_module
    requested = function_filter.upper() if function_filter else None
    records: list[TpuBlockMatch] = []

    for path_value in sorted((Path(path) for path in tpu_paths), key=lambda path: str(path)):
        obj = load_tpu_object(path_value)
        for block in obj.blocks:
            procedure = (
                obj.code_symbols[block.index].name
                if block.index < len(obj.code_symbols)
                else f"BLOCK{block.index}"
            )
            if requested and requested not in procedure.upper():
                continue
            if block.size < minimum_block_size:
                continue
            start = block.code_offset
            code = obj.code[start:start + block.size]
            mask = build_mask(len(code), obj.fixups, window_start=start)
            fixed_bytes = sum(value != 0 for value in mask)
            if fixed_bytes < minimum_fixed_bytes:
                continue

            locations: list[TpuBlockLocation] = []
            for offset in locate_code_window(overlay, code, mask):
                descriptor = _containing_descriptor(
                    offset, block.size, target.descriptors
                )
                if descriptor is not None:
                    locations.append(TpuBlockLocation(
                        image="overlay",
                        file_offset=offset,
                        image_offset=offset - descriptor.file_offset,
                        overlay_index=descriptor.index,
                    ))
            for image_offset in locate_code_window(resident, code, mask):
                locations.append(TpuBlockLocation(
                    image="resident",
                    file_offset=target.mz.header.header_size + image_offset,
                    image_offset=image_offset,
                ))
            if locations:
                records.append(TpuBlockMatch(
                    unit=path_value.stem,
                    procedure=procedure,
                    block_index=block.index,
                    size=block.size,
                    fixed_bytes=fixed_bytes,
                    locations=tuple(locations),
                ))

    return TpuScanResult(
        overlay_count=len(target.descriptors),
        matches=tuple(records),
    )


def scan_tpu_directory(
    executable_path: str | Path,
    overlay_path: str | Path,
    tpu_directory: str | Path,
    **kwargs,
) -> TpuScanResult:
    directory = Path(tpu_directory)
    tpu_paths = sorted(
        path for path in directory.iterdir()
        if path.is_file() and path.suffix.upper() == ".TPU"
    )
    if not tpu_paths:
        raise FileNotFoundError(f"no TPU files found in {directory}")
    return scan_tpu_blocks(
        Path(executable_path).read_bytes(),
        Path(overlay_path).read_bytes(),
        tpu_paths,
        **kwargs,
    )


def format_tpu_scan(result: TpuScanResult, *, verbose: bool = False) -> str:
    units: dict[str, dict[str, int]] = {}
    for match in result.matches:
        row = units.setdefault(match.unit, {"unique": 0, "ambiguous": 0, "bytes": 0})
        if match.is_unique:
            row["unique"] += 1
            row["bytes"] += match.size
        else:
            row["ambiguous"] += 1

    lines = [
        "Unit          Unique  Ambiguous  Exact bytes",
    ]
    for unit in sorted(units):
        row = units[unit]
        lines.append(
            f"{unit:12}  {row['unique']:6d}  {row['ambiguous']:9d}  {row['bytes']:11d}"
        )
    lines.extend((
        "",
        f"{result.unique_count} uniquely located block(s); "
        f"{result.ambiguous_count} ambiguous block(s); "
        f"{result.overlay_count} validated overlay unit(s)",
    ))

    if verbose:
        lines.append("")
        for match in result.matches:
            rendered_locations = []
            for location in match.locations:
                if location.image == "overlay":
                    rendered_locations.append(
                        f"ovr{location.overlay_index:03d}+0x{location.image_offset:X}"
                    )
                else:
                    rendered_locations.append(
                        f"resident+0x{location.image_offset:X}"
                    )
            lines.append(
                f"{match.unit}.{match.procedure} block={match.block_index} "
                f"size={match.size} -> {', '.join(rendered_locations)}"
            )
    return "\n".join(lines)


def write_tpu_scan_json(result: TpuScanResult, path: str | Path) -> None:
    payload = {
        "overlay_count": result.overlay_count,
        "unique_blocks": result.unique_count,
        "ambiguous_blocks": result.ambiguous_count,
        "matches": [asdict(match) for match in result.matches],
    }
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
