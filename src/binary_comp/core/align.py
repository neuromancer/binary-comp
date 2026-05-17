"""Sequence alignment helpers."""

from __future__ import annotations


def lcs_align(left: list[str], right: list[str]) -> list[tuple[int, int]]:
    """Align two sequences using longest common subsequence."""
    rows = len(left)
    cols = len(right)
    dp = [[0] * (cols + 1) for _ in range(rows + 1)]
    for i in range(1, rows + 1):
        for j in range(1, cols + 1):
            if left[i - 1] == right[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    matches: list[tuple[int, int]] = []
    i = rows
    j = cols
    while i > 0 and j > 0:
        if left[i - 1] == right[j - 1]:
            matches.append((i - 1, j - 1))
            i -= 1
            j -= 1
        elif dp[i - 1][j] > dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    matches.reverse()
    return matches
