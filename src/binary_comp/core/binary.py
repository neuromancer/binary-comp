"""Position-aware comparison helpers for arbitrary binary images.

These metrics deliberately describe positional identity, not edit-distance or
semantic similarity.  A shifted region therefore remains visible instead of
being presented as reconstruction progress that has not actually been linked
at the target address yet.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryComparison:
    original_size: int
    rebuilt_size: int
    matching_positions: int
    differing_positions: int
    differing_runs: int
    common_prefix: int
    common_suffix: int

    @property
    def compared_size(self) -> int:
        return max(self.original_size, self.rebuilt_size)

    @property
    def positional_identity(self) -> float:
        if self.compared_size == 0:
            return 100.0
        return self.matching_positions * 100.0 / self.compared_size

    @property
    def exact(self) -> bool:
        return self.differing_positions == 0


def compare_binary(original: bytes, rebuilt: bytes) -> BinaryComparison:
    """Compare bytes at the same file/image offsets."""

    shared_size = min(len(original), len(rebuilt))
    compared_size = max(len(original), len(rebuilt))
    matching_positions = sum(
        original[index] == rebuilt[index]
        for index in range(shared_size)
    )

    common_prefix = 0
    while (
        common_prefix < shared_size
        and original[common_prefix] == rebuilt[common_prefix]
    ):
        common_prefix += 1

    common_suffix = 0
    suffix_limit = shared_size - common_prefix
    while (
        common_suffix < suffix_limit
        and original[len(original) - common_suffix - 1]
        == rebuilt[len(rebuilt) - common_suffix - 1]
    ):
        common_suffix += 1

    differing_runs = 0
    in_difference = False
    for index in range(compared_size):
        differs = (
            index >= len(original)
            or index >= len(rebuilt)
            or original[index] != rebuilt[index]
        )
        if differs and not in_difference:
            differing_runs += 1
        in_difference = differs

    return BinaryComparison(
        original_size=len(original),
        rebuilt_size=len(rebuilt),
        matching_positions=matching_positions,
        differing_positions=compared_size - matching_positions,
        differing_runs=differing_runs,
        common_prefix=common_prefix,
        common_suffix=common_suffix,
    )


def format_binary_comparison(
    comparison: BinaryComparison,
    *,
    title: str = "Binary positional comparison",
) -> str:
    delta = comparison.rebuilt_size - comparison.original_size
    delta_text = f"{delta:+d}"
    return "\n".join(
        [
            title,
            f"  original size:       {comparison.original_size}",
            f"  rebuilt size:        {comparison.rebuilt_size} ({delta_text})",
            f"  matching positions:  {comparison.matching_positions} / "
            f"{comparison.compared_size} "
            f"({comparison.positional_identity:.4f}%)",
            f"  differing positions: {comparison.differing_positions} "
            f"in {comparison.differing_runs} run(s)",
            f"  common prefix:       {comparison.common_prefix}",
            f"  common suffix:       {comparison.common_suffix}",
            f"  exact:               {'yes' if comparison.exact else 'no'}",
        ]
    )
