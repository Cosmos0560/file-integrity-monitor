"""Measure fim on this machine: throughput, Python memory and the cost of loading a large baseline.

Every number in docs/performance.md comes from a run of this script (PLAN.md Phase 6, D11); the
exact command is printed with each table. The script writes only inside one temporary directory
that it creates and removes, and it runs the real use cases (``run_baseline``, ``run_check``,
``read_verified_baseline``) on real files, never a mock.

    python scripts/bench.py throughput  [--files 1000,10000,100000] [--large-mib 16,64,256]
    python scripts/bench.py memory      [--files 1000,10000,100000]
    python scripts/bench.py baseline-load [--records 50000,200000,400000]
    python scripts/bench.py all

``throughput`` measures wall time with no tracing (tracing would slow everything down),
``memory`` measures peak Python memory with ``tracemalloc`` in a separate pass, and
``baseline-load`` builds a signed baseline of a given number of synthetic records with the real
encoder, then loads it in a fresh process, once to read the operating system's peak working set
and once under ``tracemalloc``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from fim import __version__
from fim.app.baseline import (
    BaselineRequest,
    InitKeyRequest,
    read_verified_baseline,
    run_baseline,
    run_init_key,
)
from fim.app.check import CheckRequest, run_check
from fim.core.limits import DEFAULT_LIMITS, MAX_FILES_CEILING, MIB
from fim.core.models import Baseline, BaselineHeader, HashStatus, Policy, RootPolicy, SymlinkPolicy
from fim.core.pathrules import Flavour, validate_user_path
from fim.core.policy import build_policy
from fim.fs.observe import DirListing, FsProblem, HashResult, RawStat
from fim.platform.clock import SystemClock
from fim.services.baseline_codec import encode_baseline
from fim.services.keystore import decode_key_file, encode_key_file, generate_key
from fim.services.scanner import scan

FILES_PER_DIRECTORY = 100
SMALL_FILE_BYTES = 1024


# ---- the machine ---------------------------------------------------------------------------------


def total_ram_bytes() -> int | None:
    """Physical memory, or None if the platform does not say."""
    if sys.platform == "win32":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [  # ctypes reads the class attribute
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
        return None
    else:
        try:
            return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (ValueError, OSError, AttributeError):
            return None


def cpu_name() -> str:
    if sys.platform == "win32":
        import winreg

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            with key:
                value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            return str(value).strip()
        except OSError:
            return platform.processor() or "unknown"
    else:
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
        return platform.processor() or "unknown"


def peak_working_set_bytes() -> int | None:
    """The peak resident memory of this process so far (Windows: working set; POSIX: ru_maxrss)."""
    if sys.platform == "win32":
        import ctypes

        class Counters(ctypes.Structure):
            _fields_ = [  # ctypes reads the class attribute
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi = ctypes.windll.psapi
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(Counters),
            ctypes.c_ulong,
        ]
        handle = kernel32.GetCurrentProcess()
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return int(counters.PeakWorkingSetSize)
        return None
    else:
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(peak) * (1 if sys.platform == "darwin" else 1024)


def describe_machine(workdir: str) -> list[str]:
    ram = total_ram_bytes()
    memory = f", {ram / 1024**3:.1f} GiB RAM" if ram else ""
    return [
        f"- date: {datetime.now(UTC).strftime('%Y-%m-%d')} (UTC)",
        f"- machine: {cpu_name()}, {os.cpu_count()} logical processors{memory}",
        f"- operating system: {platform.platform()}",
        f"- Python: {platform.python_implementation()} {platform.python_version()}",
        f"- fim: {__version__}",
        f"- trees and baselines are made under: {workdir}",
    ]


# ---- helpers -------------------------------------------------------------------------------------


def mib(value: float) -> str:
    return f"{value / MIB:.1f}"


def seconds(value: float) -> str:
    return f"{value:.2f}"


def summarise(samples: Sequence[float], unit: Callable[[float], str] = seconds) -> str:
    """The median, with the range when there is more than one sample."""
    if len(samples) == 1:
        return unit(samples[0])
    return f"{unit(statistics.median(samples))} ({unit(min(samples))} to {unit(max(samples))})"


def table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def make_small_tree(root: Path, files: int) -> None:
    """``files`` files of 1 KiB, 100 to a directory, two levels deep, content fixed per index."""
    for index in range(files):
        group, offset = divmod(index, FILES_PER_DIRECTORY)
        directory = root / f"d{group // 50:04d}" / f"s{group % 50:02d}"
        if offset == 0:
            directory.mkdir(parents=True, exist_ok=True)
        block = hashlib.sha256(index.to_bytes(8, "big")).digest()
        (directory / f"f{index:07d}.dat").write_bytes(block * (SMALL_FILE_BYTES // len(block)))


def make_large_file(path: Path, size: int) -> None:
    block = hashlib.sha256(b"fim bench block").digest() * (MIB // 32)
    with path.open("wb") as handle:
        for _ in range(size // MIB):
            handle.write(block)


class Workspace:
    """A tree, a configuration, a key and a baseline path, all inside one directory."""

    def __init__(self, base: Path, name: str) -> None:
        self.base = base / name
        self.watched = self.base / "watched"
        self.state = self.base / "state"
        self.watched.mkdir(parents=True)
        self.state.mkdir()
        self.config = self.state / "config.yaml"
        self.key = self.state / "fim.key"
        self.baseline = self.state / "bench.baseline"
        self.config.write_text(
            "version: 1\n"
            'host_label: "bench"\n'
            f"key_file: {json.dumps(str(self.key))}\n"
            "paths:\n"
            f"  - path: {json.dumps(str(self.watched))}\n"
            "    severity: high\n",
            encoding="utf-8",
        )

    def init_key(self) -> None:
        run_init_key(
            InitKeyRequest(key_file=str(self.key), config_path=str(self.config), force=False)
        )

    def baseline_request(self) -> BaselineRequest:
        return BaselineRequest(
            config_path=str(self.config),
            baseline_path=str(self.baseline),
            key_file=None,
            force=True,
        )

    def check_request(self) -> CheckRequest:
        return CheckRequest(
            baseline_path=str(self.baseline), key_file=None, config_path=str(self.config)
        )


def timed(action: Callable[[], Any]) -> tuple[float, Any]:
    started = time.perf_counter()
    result = action()
    return time.perf_counter() - started, result


# ---- throughput ----------------------------------------------------------------------------------


def hashlib_reference(total_mib: int = 256) -> float:
    """SHA-256 over memory, 1 MiB at a time: the ceiling for MiB/s with no file system involved."""
    block = bytes(MIB)
    digest = hashlib.sha256()
    started = time.perf_counter()
    for _ in range(total_mib):
        digest.update(block)
    return total_mib / (time.perf_counter() - started)


def small_workspace(base: Path, count: int) -> Workspace:
    workspace = Workspace(base, f"small-{count}")
    make_small_tree(workspace.watched, count)
    workspace.init_key()
    return workspace


def bench_throughput(
    base: Path, files: Sequence[int], large: Sequence[int], repeats: int
) -> dict[int, Workspace]:
    """Time baseline and check; return the trees so the memory pass can reuse them."""
    clock = SystemClock()
    trees: dict[int, Workspace] = {}
    print(f"## Many small files ({SMALL_FILE_BYTES} bytes each)\n")
    print(
        "The first baseline of a tree is shown apart from the later ones: on a machine with "
        "real-time\nmalware protection every file is scanned the first time it is opened, which "
        "can dominate a first run\nover files that were just written. Later runs and every check "
        f"are warm ({repeats} runs of each, median and range).\n"
    )
    rows: list[list[str]] = []
    for count in files:
        workspace = small_workspace(base, count)
        trees[count] = workspace
        baseline_times: list[float] = []
        check_times: list[float] = []
        size = 0
        records = 0
        for _ in range(repeats + 1):
            elapsed, outcome = timed(partial(run_baseline, workspace.baseline_request(), clock))
            baseline_times.append(elapsed)
            size, records = outcome.size_bytes, outcome.records
        for _ in range(repeats):
            elapsed, checked = timed(partial(run_check, workspace.check_request(), clock))
            check_times.append(elapsed)
            if checked.report.findings or checked.exit_code != 0:
                raise SystemExit("the benchmark tree changed while it was being measured")
        first, later = baseline_times[0], baseline_times[1:]
        rows.append(
            [
                f"{count:,}",
                f"{records:,}",
                seconds(first),
                summarise(later),
                f"{records / statistics.median(later):,.0f}",
                summarise(check_times),
                f"{records / statistics.median(check_times):,.0f}",
                mib(size),
                f"{size / records:,.0f}",
            ]
        )
    print(
        table(
            [
                "files",
                "records",
                "baseline, first run s",
                "baseline, later runs s",
                "records/s",
                "check s",
                "records/s",
                "baseline MiB",
                "bytes/record",
            ],
            rows,
        )
    )
    print("\n(records = files + directories; 100 files to a directory, two levels deep)\n")

    if large:
        print("## One large file\n")
        reference = hashlib_reference()
        rows = []
        for size_mib in large:
            workspace = Workspace(base, f"large-{size_mib}")
            make_large_file(workspace.watched / "big.bin", size_mib * MIB)
            workspace.init_key()
            times: list[float] = []
            for _ in range(repeats + 1):
                elapsed, _outcome = timed(
                    partial(run_baseline, workspace.baseline_request(), clock)
                )
                times.append(elapsed)
            first, later = times[0], times[1:]
            rows.append(
                [
                    f"{size_mib}",
                    seconds(first),
                    summarise(later),
                    f"{size_mib / statistics.median(later):,.0f}",
                ]
            )
            shutil.rmtree(workspace.base)
        print(table(["file MiB", "baseline, first run s", "baseline, later runs s", "MiB/s"], rows))
        print(
            "\nMiB/s is the file size over the median later run, so it includes the fixed cost of "
            "a baseline\n(configuration, key, one write). Reference: hashlib.sha256 over memory, "
            f"no file system, {reference:,.0f} MiB/s.\n"
        )
    return trees


# ---- peak Python memory --------------------------------------------------------------------------


def bench_memory(base: Path, files: Sequence[int], trees: dict[int, Workspace]) -> None:
    clock = SystemClock()
    print("## Peak Python memory during baseline and check (tracemalloc)\n")
    print(
        "Each figure is the peak of Python allocations while that command ran, in a pass of its "
        "own on the\nsame tree (tracing slows the run, so these are not the timed runs).\n"
    )
    rows: list[list[str]] = []
    for count in files:
        workspace = trees.get(count) or small_workspace(base, count)
        peaks: dict[str, int] = {}
        for label, action in (
            ("baseline", partial(run_baseline, workspace.baseline_request(), clock)),
            ("check", partial(run_check, workspace.check_request(), clock)),
        ):
            tracemalloc.start()
            tracemalloc.reset_peak()
            action()
            peaks[label] = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
        rows.append([f"{count:,}", mib(peaks["baseline"]), mib(peaks["check"])])
    print(table(["files", "baseline peak MiB", "check peak MiB"], rows))
    print()


# ---- loading a large baseline and checking at scale (D11) ----------------------------------------

SYNTHETIC_ROOT = "/srv"
FILES_PER_LEAF = 1000
LEAVES_PER_TOP = 50
FILES_PER_TOP = FILES_PER_LEAF * LEAVES_PER_TOP
SYNTHETIC_MTIME_NS = 1_760_000_000_000_000_000
_NOT_FOUND = FsProblem("ENOENT", vanished=True, denied=False)
_TOP = re.compile(r"d(\d{4})")
_LEAF = re.compile(r"d(\d{4})/s(\d{2})")
_FILE = re.compile(r"d(\d{4})/s(\d{2})/f(\d{7})\.dat")


class SyntheticView:
    """A tree of ``count`` files that exists only as arithmetic: nothing is stored per file.

    Layout: ``/srv/dNNNN/sNN/fNNNNNNN.dat``, 1000 files to a leaf directory, 50 leaves to a top
    directory. It implements the scanner's file system interface, so the real scanner, baseline
    encoder, MAC check and comparison run on it unchanged.
    """

    def __init__(self, count: int) -> None:
        self.count = count

    def _directory(self, ino: int) -> RawStat:
        return RawStat(
            st_mode=stat.S_IFDIR | 0o755,
            size=0,
            mtime_ns=SYNTHETIC_MTIME_NS,
            dev=1,
            ino=ino,
            nlink=1,
            uid=1000,
            gid=1000,
            file_attributes=None,
            reparse_tag=None,
        )

    def _file(self, index: int) -> RawStat:
        return RawStat(
            st_mode=stat.S_IFREG | 0o644,
            size=1024 + index % 4096,
            mtime_ns=SYNTHETIC_MTIME_NS + index * 1_000_003,
            dev=1,
            ino=1_000_000 + index,
            nlink=1,
            uid=1000,
            gid=1000,
            file_attributes=None,
            reparse_tag=None,
        )

    def lstat(self, path: str) -> RawStat | FsProblem:
        if path == SYNTHETIC_ROOT:
            return self._directory(1)
        relative = path[len(SYNTHETIC_ROOT) + 1 :] if path.startswith(SYNTHETIC_ROOT + "/") else ""
        if (found := _FILE.fullmatch(relative)) is not None:
            top, leaf, index = (int(group) for group in found.groups())
            exists = index < self.count and index // FILES_PER_TOP == top
            if exists and (index // FILES_PER_LEAF) % LEAVES_PER_TOP == leaf:
                return self._file(index)
        elif (found := _LEAF.fullmatch(relative)) is not None:
            top, leaf = int(found.group(1)), int(found.group(2))
            if top * FILES_PER_TOP + leaf * FILES_PER_LEAF < self.count and leaf < LEAVES_PER_TOP:
                return self._directory(10_000 + top * LEAVES_PER_TOP + leaf)
        elif (found := _TOP.fullmatch(relative)) is not None:
            top = int(found.group(1))
            if top * FILES_PER_TOP < self.count:
                return self._directory(100 + top)
        return _NOT_FOUND

    def stat_target(self, path: str) -> RawStat | FsProblem:
        return self.lstat(path)

    def read_link(self, path: str) -> str | FsProblem:
        del path  # there are no links in the synthetic tree
        return _NOT_FOUND

    def list_dir(self, path: str, limit: int) -> DirListing | FsProblem:
        names: list[str] = []
        relative = path[len(SYNTHETIC_ROOT) + 1 :] if path.startswith(SYNTHETIC_ROOT + "/") else ""
        if path == SYNTHETIC_ROOT:
            tops = -(-self.count // FILES_PER_TOP)
            names = [f"d{top:04d}" for top in range(tops)]
        elif (found := _TOP.fullmatch(relative)) is not None:
            base = int(found.group(1)) * FILES_PER_TOP
            for leaf in range(LEAVES_PER_TOP):
                if base + leaf * FILES_PER_LEAF < self.count:
                    names.append(f"s{leaf:02d}")
        elif (found := _LEAF.fullmatch(relative)) is not None:
            base = int(found.group(1)) * FILES_PER_TOP + int(found.group(2)) * FILES_PER_LEAF
            names = [
                f"f{index:07d}.dat"
                for index in range(base, base + FILES_PER_LEAF)
                if index < self.count
            ]
        else:
            return _NOT_FOUND
        return DirListing(tuple(names[:limit]), len(names) > limit)

    def hash_file(
        self,
        path: str,
        expected: RawStat,
        *,
        max_bytes: int,
        should_stop: Callable[[], bool],
        follow: bool,
    ) -> HashResult:
        del path, max_bytes, should_stop, follow  # the interface asks; the content is arithmetic
        index = expected.ino - 1_000_000
        return HashResult(
            status=HashStatus.OK,
            sha256=hashlib.sha256(index.to_bytes(8, "big")).hexdigest(),
            bytes_read=expected.size,
            size=expected.size,
            mtime_ns=expected.mtime_ns,
            error=None,
            detail="",
        )


def synthetic_policy(count: int) -> Policy:
    entries = count + count // FILES_PER_LEAF + count // FILES_PER_TOP + 8
    limits = DEFAULT_LIMITS.with_overrides({"max_files": max(entries, DEFAULT_LIMITS.max_files)})
    root = RootPolicy(path=validate_user_path(SYNTHETIC_ROOT, Flavour.POSIX))
    return build_policy([root], [], SymlinkPolicy.NEVER, limits)


def build_synthetic_baseline(directory: Path, count: int) -> tuple[Path, Path, int, int]:
    """Scan a synthetic tree with the real scanner and sign the result with the real encoder.

    Returns (baseline file, key file, bytes, records).
    """
    key_path = directory / "fim.key"
    baseline_path = directory / "synthetic.baseline"
    key = generate_key()
    key_path.write_bytes(encode_key_file(key))
    if sys.platform != "win32":
        key_path.chmod(0o600)
    policy = synthetic_policy(count)
    result = scan(policy, SystemClock(), view=SyntheticView(count))
    if not result.complete:
        raise SystemExit("the synthetic scan did not finish: raise the limits or lower the count")
    header = BaselineHeader(
        tool_version=__version__,
        created_at=datetime.now(UTC),
        sequence=1,
        host="bench",
        platform="linux",
        policy=policy,
        complete=True,
        limits=policy.limits,
    )
    encoded = encode_baseline(Baseline(header=header, records=result.records), key)
    baseline_path.write_bytes(encoded.data)
    return baseline_path, key_path, len(encoded.data), len(result.records)


def load_worker(mode: str, baseline: str, key_file: str, count: int, trace: bool) -> None:
    """Run in a fresh process: load the baseline (``load``) or run a whole check (``check``)."""
    key = decode_key_file(Path(key_file).read_bytes())
    if trace:
        tracemalloc.start()
    started = time.perf_counter()
    result: dict[str, Any] = {}
    if mode == "load":
        verified = read_verified_baseline(baseline, key, key_file)
        result["records"] = len(verified.decoded.baseline.records)
    else:
        request = CheckRequest(baseline_path=baseline, key_file=key_file, config_path=None)
        outcome = run_check(request, SystemClock(), view=SyntheticView(count))
        result["findings"] = len(outcome.report.findings)
        result["exit_code"] = int(outcome.exit_code)
    result["seconds"] = time.perf_counter() - started
    result["peak_working_set"] = peak_working_set_bytes()
    if trace:
        result["tracemalloc_peak"] = tracemalloc.get_traced_memory()[1]
    print(json.dumps(result))


def run_worker(mode: str, baseline: Path, key: Path, count: int, trace: bool) -> dict[str, Any]:
    script = str(Path(__file__).resolve())
    command = [sys.executable, "-B", script, "_worker", mode, str(baseline), str(key), str(count)]
    if trace:
        command.append("--trace")
    completed = subprocess.run(  # our own interpreter and our own script
        command, capture_output=True, text=True, check=True, cwd=str(baseline.parent)
    )
    parsed = json.loads(completed.stdout.strip().splitlines()[-1])
    if not isinstance(parsed, dict):
        raise SystemExit("the worker printed something unexpected")
    if mode == "check" and (parsed["findings"] != 0 or parsed["exit_code"] != 0):
        raise SystemExit("the synthetic check was not clean: the view and the baseline disagree")
    return parsed


def bench_baseline_load(base: Path, record_counts: Sequence[int]) -> None:
    print("## Loading a baseline and running a whole check, at scale (fresh process each)\n")
    print(
        "The trees are synthetic: the real scanner, encoder, MAC check and comparison run on a "
        "file system that\nexists only as arithmetic, so that sizes up to the baseline size limit "
        "can be made without a million real files.\n`load` is read, verify the MAC and parse; "
        "`check` is the whole command against an identical tree (no findings).\n"
        "Peak working set is what the operating system reports for the process; "
        "tracemalloc is Python's own count.\n"
    )
    rows: list[list[str]] = []
    for count in record_counts:
        directory = base / f"load-{count}"
        directory.mkdir()
        baseline, key, size, records = build_synthetic_baseline(directory, count)
        cells = [f"{records:,}", mib(size)]
        for mode in ("load", "check"):
            plain = run_worker(mode, baseline, key, count, trace=False)
            traced = run_worker(mode, baseline, key, count, trace=True)
            peak_set = plain["peak_working_set"]
            cells += [
                seconds(plain["seconds"]),
                mib(peak_set) if peak_set is not None else "n/a",
                mib(traced["tracemalloc_peak"]),
            ]
        rows.append(cells)
        shutil.rmtree(directory)
    print(
        table(
            [
                "records",
                "baseline MiB",
                "load s",
                "load peak working set MiB",
                "load tracemalloc MiB",
                "check s",
                "check peak working set MiB",
                "check tracemalloc MiB",
            ],
            rows,
        )
    )
    default_files = DEFAULT_LIMITS.max_files
    print(f"\n(MAX_FILES ceiling {MAX_FILES_CEILING:,}; default MAX_FILES {default_files:,})\n")


# ---- main ----------------------------------------------------------------------------------------


def parse_numbers(text: str) -> list[int]:
    return [int(part) for part in text.split(",") if part.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("throughput", "memory", "baseline-load", "all"):
        sub = commands.add_parser(name)
        sub.add_argument("--files", default="1000,10000,100000", type=parse_numbers)
        sub.add_argument("--large-mib", default="16,64,256", type=parse_numbers)
        sub.add_argument("--records", default="50000,200000,400000", type=parse_numbers)
        sub.add_argument("--repeats", default=3, type=int)
        sub.add_argument("--workdir", default=None, help="parent directory for the trees")
    worker = commands.add_parser("_worker")
    worker.add_argument("mode", choices=("load", "check"))
    worker.add_argument("baseline")
    worker.add_argument("key")
    worker.add_argument("count", type=int)
    worker.add_argument("--trace", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "_worker":
        load_worker(args.mode, args.baseline, args.key, args.count, args.trace)
        return 0

    base = Path(tempfile.mkdtemp(prefix="fim-bench-", dir=args.workdir))
    try:
        typed = argv if argv is not None else sys.argv[1:]
        print(f"# fim benchmark\n\ncommand: `python scripts/bench.py {' '.join(typed)}`\n")
        print("\n".join(describe_machine(str(base.parent))))
        print()
        trees: dict[int, Workspace] = {}
        if args.command in ("throughput", "all"):
            trees = bench_throughput(base, args.files, args.large_mib, args.repeats)
        if args.command in ("memory", "all"):
            bench_memory(base, args.files, trees)
        if args.command in ("baseline-load", "all") and args.records:
            bench_baseline_load(base, args.records)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
