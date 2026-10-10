"""scripts/bench.py: exercised on a tiny tree, so the script that produces the numbers in
docs/performance.md cannot rot (PLAN.md Phase 6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import bench
from fim.fs.observe import FsProblem


def test_bench_throughput_and_memory_run_on_a_tiny_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = bench.main(
        [
            "all",
            "--files",
            "30",
            "--large-mib",
            "1",
            "--repeats",
            "1",
            "--records",
            "",
            "--workdir",
            str(tmp_path),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "## Many small files" in out
    assert "## One large file" in out
    assert "## Peak Python memory" in out
    assert "command: `python scripts/bench.py all" in out
    assert list(tmp_path.iterdir()) == []  # the script removes its own directory


def test_the_synthetic_tree_checks_clean_through_the_real_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline, key, size, records = bench.build_synthetic_baseline(tmp_path, 2500)
    assert size > 0
    assert records > 2500  # the files and their directories
    for mode in ("load", "check"):
        bench.load_worker(mode, str(baseline), str(key), 2500, trace=False)
        result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert result["seconds"] >= 0
        assert result["peak_working_set"] is None or result["peak_working_set"] > 0
        if mode == "load":
            assert result["records"] == records
        else:
            assert result["findings"] == 0
            assert result["exit_code"] == 0


def test_the_synthetic_view_describes_missing_paths_as_missing() -> None:
    view = bench.SyntheticView(10)
    assert not isinstance(view.lstat("/srv/d0000/s00/f0000009.dat"), FsProblem)
    assert isinstance(view.lstat("/srv/d0000/s00/f0000010.dat"), FsProblem)
    assert isinstance(view.lstat("/srv/d0001"), FsProblem)
    assert isinstance(view.lstat("/elsewhere"), FsProblem)
    assert isinstance(view.list_dir("/srv/nothing", 10), FsProblem)
    assert isinstance(view.read_link("/srv"), FsProblem)


@pytest.mark.slow
def test_bench_baseline_load_runs_its_workers_in_fresh_processes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = bench.main(["baseline-load", "--records", "1500", "--workdir", str(tmp_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "| 1,5" in out  # the record count, with the directories added
    assert "check peak working set MiB" in out
