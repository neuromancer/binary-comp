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
    assert report.missing_asm == 0
    assert "sample_function" in text
    assert "Average similarity: 100.00%" in text


def test_similarity_report_filter_limits_rows(fixture_root, sample_binaries):
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

    report = generate_similarity_report(
        target,
        SimilarityReportOptions(build=False, file_filter="does-not-match"),
    )

    assert report.rows == ()
    assert report.compared == 0


def test_similarity_report_counts_missing_asm(fixture_root, sample_binaries, tmp_path):
    original, rebuilt = sample_binaries
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(tmp_path / "missing-code"),
        build=BuildConfig(),
    )

    report = generate_similarity_report(target, SimilarityReportOptions(build=False))

    assert report.compared == 0
    assert report.missing_asm == 1
    assert report.rows[0].status == "MISSING ASM"
