"""Locate relocation-masked Turbo Pascal code blocks in DOS target images."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from binary_comp.analyzers.tp_overlay import TpOverlayDescriptor, parse_tp_overlay
from binary_comp.analyzers.tpu import build_mask, load_tpu_object, locate_code_window
from binary_comp.core.mz import parse_mz


@dataclass(frozen=True)
class TpuScanRegion:
    """One bounded code region in either the resident or overlay image."""

    image: str
    start: int
    end: int
    label: str
    index: int | None = None


@dataclass(frozen=True)
class TpuScanRegions:
    """Explicit code bounds for formats without a resident TPOV directory."""

    resident: tuple[TpuScanRegion, ...]
    overlay: tuple[TpuScanRegion, ...]


@dataclass(frozen=True)
class TpuBlockLocation:
    image: str
    file_offset: int
    image_offset: int
    overlay_index: int | None = None
    region: str | None = None
    region_index: int | None = None


@dataclass(frozen=True)
class TpuBlockMatch:
    unit: str
    procedure: str
    block_index: int
    size: int
    fixed_bytes: int
    locations: tuple[TpuBlockLocation, ...]
    resolution: str | None = None

    @property
    def is_unique(self) -> bool:
        return len(self.locations) == 1

    @property
    def is_missing(self) -> bool:
        return not self.locations

    @property
    def status(self) -> str:
        if self.is_missing:
            return "missing"
        return "unique" if self.is_unique else "ambiguous"


@dataclass(frozen=True)
class TpuScanResult:
    overlay_count: int
    matches: tuple[TpuBlockMatch, ...]

    @property
    def unique_count(self) -> int:
        return sum(match.is_unique for match in self.matches)

    @property
    def ambiguous_count(self) -> int:
        return sum(len(match.locations) > 1 for match in self.matches)

    @property
    def missing_count(self) -> int:
        return sum(match.is_missing for match in self.matches)

    @property
    def exact_bytes(self) -> int:
        return sum(match.size for match in self.matches if match.is_unique)


def _config_int(value: Any, label: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise ValueError(f"{label} must be an integer or integer string")


def parse_tpu_scan_regions(payload: dict[str, Any]) -> TpuScanRegions:
    """Parse a generic resident/overlay region manifest.

    A larger report may embed the manifest under ``scan_regions``. Region
    labels and indices are opaque identifiers supplied by the calling project;
    binary-comp does not attach game-specific meaning to either.
    """

    section = payload.get("scan_regions", payload)
    if not isinstance(section, dict):
        raise ValueError("scan_regions must be an object")

    def parse_image(image: str) -> tuple[TpuScanRegion, ...]:
        raw = section.get(image, [])
        if not isinstance(raw, list):
            raise ValueError(f"scan_regions.{image} must be a list")
        regions: list[TpuScanRegion] = []
        for ordinal, item in enumerate(raw):
            label = f"scan_regions.{image}[{ordinal}]"
            if not isinstance(item, dict):
                raise ValueError(f"{label} must be an object")
            start = _config_int(item.get("start"), f"{label}.start")
            end = _config_int(item.get("end"), f"{label}.end")
            if start < 0 or end <= start:
                raise ValueError(f"{label} must satisfy 0 <= start < end")
            name = item.get("label", f"{image}-{ordinal}")
            if not isinstance(name, str) or not name:
                raise ValueError(f"{label}.label must be a non-empty string")
            index_value = item.get("index")
            index = None if index_value is None else _config_int(index_value, f"{label}.index")
            regions.append(TpuScanRegion(image, start, end, name, index))
        regions.sort(key=lambda region: (region.start, region.end, region.label))
        for left, right in zip(regions, regions[1:]):
            if left.end > right.start:
                raise ValueError(
                    f"overlapping {image} regions {left.label!r} and {right.label!r}"
                )
        return tuple(regions)

    regions = TpuScanRegions(
        resident=parse_image("resident"),
        overlay=parse_image("overlay"),
    )
    if not regions.resident and not regions.overlay:
        raise ValueError("scan region manifest contains no regions")
    return regions


def load_tpu_scan_regions(path: str | Path) -> TpuScanRegions:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("scan region manifest must contain a JSON object")
    return parse_tpu_scan_regions(payload)


def _descriptor_regions(
    descriptors: tuple[TpOverlayDescriptor, ...],
) -> tuple[TpuScanRegion, ...]:
    return tuple(
        TpuScanRegion(
            image="overlay",
            start=descriptor.file_offset,
            end=descriptor.code_end,
            label=f"ovr{descriptor.index:03d}",
            index=descriptor.index,
        )
        for descriptor in descriptors
    )


def _validate_region_bounds(
    regions: tuple[TpuScanRegion, ...], size: int, image: str
) -> None:
    for region in regions:
        if region.image != image:
            raise ValueError(
                f"region {region.label!r} is tagged {region.image!r}, expected {image!r}"
            )
        if region.end > size:
            raise ValueError(
                f"{image} region {region.label!r} ends at 0x{region.end:X}, "
                f"past image size 0x{size:X}"
            )


def _locations_in_regions(
    data: bytes,
    code: bytes,
    mask: bytes,
    regions: tuple[TpuScanRegion, ...],
    *,
    resident_header_size: int = 0,
) -> list[TpuBlockLocation]:
    locations: list[TpuBlockLocation] = []
    for region in regions:
        window = data[region.start:region.end]
        for relative_offset in locate_code_window(window, code, mask):
            offset = region.start + relative_offset
            if region.image == "resident":
                file_offset = resident_header_size + offset
                image_offset = offset
                overlay_index = None
            else:
                file_offset = offset
                image_offset = relative_offset
                overlay_index = region.index
            locations.append(TpuBlockLocation(
                image=region.image,
                file_offset=file_offset,
                image_offset=image_offset,
                overlay_index=overlay_index,
                region=region.label,
                region_index=region.index,
            ))
    return locations


def _location_region(location: TpuBlockLocation) -> tuple[str, str | None, int | None]:
    return location.image, location.region, location.region_index


def resolve_adjacent_matches(
    matches: tuple[TpuBlockMatch, ...] | list[TpuBlockMatch],
) -> tuple[TpuBlockMatch, ...]:
    """Resolve duplicate block matches from contiguous TPU block order.

    Turbo Pascal emits consecutive procedure blocks without padding. When an
    otherwise ambiguous block has a candidate immediately after or before a
    uniquely placed adjacent block from the same unit and scan region, that
    candidate is uniquely identified. Resolution is iterative so a run of
    identical adjacent routines can be assigned from an anchored end.

    Only consecutive block indices are considered. A gap, region transition,
    or conflicting left/right constraint leaves the match ambiguous.
    """

    resolved = list(matches)
    positions_by_unit: dict[str, list[int]] = {}
    for position, match in enumerate(resolved):
        positions_by_unit.setdefault(match.unit, []).append(position)

    changed = True
    while changed:
        changed = False
        for positions in positions_by_unit.values():
            for ordinal, position in enumerate(positions):
                match = resolved[position]
                if len(match.locations) <= 1:
                    continue

                constraints: list[set[TpuBlockLocation]] = []
                evidence: list[str] = []

                if ordinal > 0:
                    previous = resolved[positions[ordinal - 1]]
                    if previous.is_unique and previous.block_index + 1 == match.block_index:
                        anchor = previous.locations[0]
                        candidates = {
                            location for location in match.locations
                            if _location_region(location) == _location_region(anchor)
                            and location.file_offset == anchor.file_offset + previous.size
                        }
                        if candidates:
                            constraints.append(candidates)
                            evidence.append("left")

                if ordinal + 1 < len(positions):
                    following = resolved[positions[ordinal + 1]]
                    if following.is_unique and match.block_index + 1 == following.block_index:
                        anchor = following.locations[0]
                        candidates = {
                            location for location in match.locations
                            if _location_region(location) == _location_region(anchor)
                            and location.file_offset + match.size == anchor.file_offset
                        }
                        if candidates:
                            constraints.append(candidates)
                            evidence.append("right")

                if not constraints:
                    continue
                candidates = set.intersection(*constraints)
                if len(candidates) != 1:
                    continue
                resolved[position] = replace(
                    match,
                    locations=(next(iter(candidates)),),
                    resolution="adjacent-" + "-".join(evidence),
                )
                changed = True

    return tuple(resolved)


def scan_tpu_blocks(
    executable: bytes,
    overlay: bytes,
    tpu_paths: list[str | Path] | tuple[str | Path, ...],
    *,
    minimum_block_size: int = 8,
    minimum_fixed_bytes: int = 8,
    function_filter: str | None = None,
    regions: TpuScanRegions | None = None,
    include_missing: bool = False,
    resolve_adjacent: bool = False,
) -> TpuScanResult:
    """Find compiled-unit code blocks in bounded resident and overlay code.

    Without explicit ``regions``, bounds are recovered from a resident TPOV
    directory. Supplying regions supports flat or externally mapped overlay
    formats while retaining the same relocation-aware matching.
    """

    if minimum_block_size < 1 or minimum_fixed_bytes < 1:
        raise ValueError("minimum block and fixed-byte sizes must be positive")
    if regions is None:
        target = parse_tp_overlay(executable, overlay)
        mz = target.mz
        scan_regions = TpuScanRegions(
            resident=(TpuScanRegion("resident", 0, len(mz.load_module), "resident"),),
            overlay=_descriptor_regions(target.descriptors),
        )
        overlay_count = len(target.descriptors)
    else:
        mz = parse_mz(executable)
        scan_regions = regions
        overlay_count = len(regions.overlay)
    resident = mz.load_module
    _validate_region_bounds(scan_regions.resident, len(resident), "resident")
    _validate_region_bounds(scan_regions.overlay, len(overlay), "overlay")
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

            locations = _locations_in_regions(
                overlay, code, mask, scan_regions.overlay
            )
            locations.extend(_locations_in_regions(
                resident,
                code,
                mask,
                scan_regions.resident,
                resident_header_size=mz.header.header_size,
            ))
            if locations or include_missing:
                records.append(TpuBlockMatch(
                    unit=path_value.stem,
                    procedure=procedure,
                    block_index=block.index,
                    size=block.size,
                    fixed_bytes=fixed_bytes,
                    locations=tuple(locations),
                ))

    matches = tuple(records)
    if resolve_adjacent:
        matches = resolve_adjacent_matches(matches)

    return TpuScanResult(
        overlay_count=overlay_count,
        matches=matches,
    )


def scan_tpu_directory(
    executable_path: str | Path,
    overlay_path: str | Path,
    tpu_directory: str | Path,
    *,
    exclude_patterns: tuple[str, ...] | list[str] = (),
    **kwargs,
) -> TpuScanResult:
    directory = Path(tpu_directory)
    tpu_paths = sorted(
        path for path in directory.iterdir()
        if path.is_file()
        and path.suffix.upper() == ".TPU"
        and not any(fnmatch.fnmatch(path.name, pattern) for pattern in exclude_patterns)
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
        row = units.setdefault(
            match.unit,
            {"examined": 0, "unique": 0, "ambiguous": 0, "missing": 0, "bytes": 0},
        )
        row["examined"] += 1
        if match.is_unique:
            row["unique"] += 1
            row["bytes"] += match.size
        elif match.is_missing:
            row["missing"] += 1
        else:
            row["ambiguous"] += 1

    lines = [
        "Unit          Examined  Unique  Ambiguous  Missing  Exact bytes",
    ]
    for unit in sorted(units):
        row = units[unit]
        lines.append(
            f"{unit:12}  {row['examined']:8d}  {row['unique']:6d}  "
            f"{row['ambiguous']:9d}  {row['missing']:7d}  {row['bytes']:11d}"
        )
    lines.extend((
        "",
        f"{result.unique_count} uniquely located block(s); "
        f"{result.ambiguous_count} ambiguous block(s); "
        f"{result.missing_count} missing block(s); "
        f"{result.exact_bytes} exact byte(s); "
        f"{result.overlay_count} validated overlay unit(s)",
    ))

    if verbose:
        lines.append("")
        for match in result.matches:
            rendered_locations = []
            for location in match.locations:
                if location.image == "overlay":
                    if location.overlay_index is not None:
                        rendered_locations.append(
                            f"ovr{location.overlay_index:03d}+0x{location.image_offset:X}"
                        )
                    else:
                        rendered_locations.append(
                            f"{location.region or 'overlay'}+0x{location.image_offset:X}"
                        )
                else:
                    rendered_locations.append(
                        f"{location.region or 'resident'}+0x{location.image_offset:X}"
                    )
            lines.append(
                f"{match.status:9} {match.unit}.{match.procedure} "
                f"block={match.block_index} size={match.size} -> "
                f"{', '.join(rendered_locations) or 'not found'}"
                f"{f' ({match.resolution})' if match.resolution else ''}"
            )
    return "\n".join(lines)


def write_tpu_scan_json(result: TpuScanResult, path: str | Path) -> None:
    payload = {
        "overlay_count": result.overlay_count,
        "counts": {
            "examined": len(result.matches),
            "unique": result.unique_count,
            "ambiguous": result.ambiguous_count,
            "missing": result.missing_count,
            "exact_bytes": result.exact_bytes,
        },
        "unique_blocks": result.unique_count,
        "ambiguous_blocks": result.ambiguous_count,
        "missing_blocks": result.missing_count,
        "matches": [asdict(match) | {"status": match.status} for match in result.matches],
    }
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
