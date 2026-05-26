from __future__ import annotations

import pytest

from binary_comp.analyzers.report import (
    SimilarityReportOptions,
    format_similarity_report,
    generate_similarity_report,
)
from binary_comp.config import BuildConfig, ProjectTarget


def test_generate_similarity_report_on_fixture_project(fixture_root, sample_binaries):
    pytest.importorskip("capstone")
    original, rebuilt = sample_binaries
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(fixture_root / "code"),
        build=BuildConfig(),
    )

    report = generate_similarity_report(target, SimilarityReportOptions(build=False))
    text = format_similarity_report(report)

    assert report.compared == 1
    assert report.at_100 == 1
    assert report.errors == 0
    assert "sample_function" in text
    assert "Average similarity: 100.00%" in text
