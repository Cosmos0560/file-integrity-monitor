# Performance

What `fim` costs on one machine, measured, with the command that produced every table. Nothing
here is an estimate: a number that is not in a table below is not claimed anywhere else in this
repository. The script is [`scripts/bench.py`](../scripts/bench.py). Its tables are pasted as
they were printed, except that the system temporary directory is shown as `<TMP>` and the
script's own headings are written as `###`.

## Machine

- date: 2026-10-10 (UTC)
- machine: Intel(R) Core(TM) Ultra 7 155U, 14 logical processors, 31.5 GiB RAM
- operating system: Windows-11-10.0.26300-SP0 (Windows 11 Pro)
- Python: CPython 3.13.14
- fim: 1.0.0, commit `b45cd2f` for the tables of sections 1 to 4 and commit `fb242b5` for the
  "before" table of section 4
- storage: one 1 TB NVMe SSD (`Get-PhysicalDisk`: MediaType SSD)
- Windows Defender real-time protection: on (`Get-MpComputerStatus`:
  `RealTimeProtectionEnabled` True); it matters below
- trees and baselines were made under `<TMP>`, the system temporary directory, on that SSD

The same machine made every table. Nothing else was deliberately running, but this is a
development laptop, not an isolated benchmark host: repeat a run before comparing small
differences.

## Method

- **What runs.** The real use cases (`run_init_key`, `run_baseline`, `run_check`) in one process,
  on real files in a new directory. Section 4 uses the real scanner, encoder, MAC check and
  comparison on a file system that exists only as arithmetic, so that baselines of a hundred
  megabytes can be made without a million files.
- **Time.** `time.perf_counter()` around one command, with no tracing. The first baseline of a
  tree is shown apart from the later ones (see below); the later runs and the checks are three
  runs each, shown as the median with the range in brackets.
- **Python memory.** The `tracemalloc` peak while the command ran, in a separate pass on the
  same tree: tracing slows a run, so memory and time are never taken from the same run.
- **Operating-system memory.** The process's peak working set as Windows reports it
  (`PeakWorkingSetSize`), in a fresh process per figure, without `tracemalloc`.
- **Cache.** The trees were just written, so reads are warm. A cold start from disk is not
  measured.
- **Time budget.** The script's configuration raises `max_run_seconds` to its ceiling of 3,600
  so that a slow first run can finish; the tool's default is 900 (section 1 says what happened
  with the default).

## 1. Many small files

Command: `python scripts/bench.py all` (one run, printed in the four sections below)

### Many small files (1024 bytes each)

The first baseline of a tree is shown apart from the later ones: on a machine with real-time
malware protection every file is scanned the first time it is opened, which can dominate a first run
over files that were just written. Later runs and every check are warm (3 runs of each, median and range). The configuration raises `max_run_seconds`
to its ceiling of 3600, so that a slow first run can finish instead of stopping at the default budget.

| files | records | baseline, first run s | baseline, later runs s | records/s | check s | records/s | baseline MiB | bytes/record |
|---|---|---|---|---|---|---|---|---|
| 1,000 | 1,012 | 14.41 | 0.34 (0.34 to 0.35) | 2,942 | 0.34 (0.34 to 0.38) | 2,966 | 0.3 | 310 |
| 10,000 | 10,103 | 123.78 | 2.54 (2.52 to 2.99) | 3,973 | 2.69 (2.65 to 2.72) | 3,751 | 3.0 | 309 |
| 100,000 | 101,021 | 1212.18 | 25.46 (23.40 to 470.07) | 3,968 | 27.49 (26.13 to 28.17) | 3,675 | 29.8 | 309 |

(records = files + directories; 100 files to a directory, two levels deep)

What the table says, and what it does not:

- **The first baseline is slow for a reason outside `fim`.** 14.4 s for 1,000 files, 123.8 s for
  10,000 and 1,212 s for 100,000 are 12 to 14 ms a file, against 0.25 to 0.34 ms a file for the later runs.
  The files had just been written and real-time protection was on, which scans a file the first
  time it is opened; I did not turn it off (it is a security setting) so the cause is the most
  likely one, not a proven one.
- **With the default 900 s budget the first baseline of the 100,000-file tree did not finish.**
  An earlier attempt of this run, before the script raised the budget, ended in this error (the
  command line reports it as exit code 4) and wrote nothing, as designed:

  ```
  fim.core.errors.LimitReachedError: the scan was incomplete (stopped after the 900 s time budget);
  nothing was written. Narrow the monitored paths, add excludes or raise a limit (up to its ceiling)
  in the configuration, or use --allow-incomplete to write a baseline marked incomplete
  ```

  On a machine that scans every file on first open, a first baseline of a large tree of new
  files needs `max_run_seconds` raised in the configuration (up to 3,600) or several runs.
- **Later runs.** About 3,000 to 4,000 records a second for both `baseline` and `check`, which is
  the cost of listing, `lstat` and opening 1 KiB files, not of hashing: see section 2.
- **One outlier.** One of the three later baseline runs of the 100,000-file tree took 470.07 s;
  the other two took 23.40 s and 25.46 s. I did not find out why. A rescan by the real-time
  protection after a definition update would fit, but I have no evidence for it. The median is
  reported as the figure, and the range shows the outlier.
- The baseline costs about 310 bytes a record for these short names; a record is the path plus
  roughly 290 bytes of fixed fields.

## 2. One large file

Command: `python scripts/bench.py all` (the same run)

### One large file

| file MiB | baseline, first run s | baseline, later runs s | MiB/s |
|---|---|---|---|
| 16 | 0.06 | 0.04 (0.04 to 0.05) | 371 |
| 64 | 0.10 | 0.08 (0.07 to 0.09) | 797 |
| 256 | 0.26 | 0.28 (0.26 to 0.29) | 905 |

MiB/s is the file size over the median later run, so it includes the fixed cost of a baseline
(configuration, key, one write). Reference: hashlib.sha256 over memory, no file system, 1,825 MiB/s.

A 256 MiB file (the largest the tool hashes by default) takes 0.28 s: about half the speed of
SHA-256 over memory. The first run of a large file was not slower than the later ones here,
which is no evidence either way about the real-time protection: its cost may be per file and not per
byte, or these files may not have been scanned; I did not investigate.

## 3. Peak Python memory

Command: `python scripts/bench.py all` (the same run)

### Peak Python memory during baseline and check (tracemalloc)

Each figure is the peak of Python allocations while that command ran, in a pass of its own on the
same tree (tracing slows the run, so these are not the timed runs).

| files | baseline peak MiB | check peak MiB |
|---|---|---|
| 1,000 | 1.5 | 1.9 |
| 10,000 | 14.4 | 16.6 |
| 100,000 | 143.8 | 165.7 |

Memory grows linearly with the number of entries: 1.46 KiB a record for `baseline` and 1.68 KiB
for `check` (which holds the baseline and the new scan) at 101,021 records. The synthetic check at
200,205 records, the default `MAX_FILES`, peaked at 346 MiB (section 4).

## 4. Loading a baseline at scale, and the D11 decision

PLAN.md D11 asked this phase to measure the peak memory of loading a baseline near
`MAX_BASELINE_BYTES` and to lower the ceiling, with the measured reason, if it is unreasonable
for a laptop. The baselines below are synthetic (records shaped like real ones, signed by the
real encoder, paths three components deep) so that sizes up to the limit can be made.

### Before: the limit was 256 MiB

Command: `python scripts/bench.py baseline-load --records 50000,200000,500000,800000 --workdir <TMP>`
(commit `fb242b5`, fim 0.1.0, `MAX_BASELINE_BYTES` still 256 MiB; the script then also printed
`fim: 0.1.0` and the date 2026-10-10)

| records | baseline MiB | load s | load peak working set MiB | load tracemalloc MiB | check s | check peak working set MiB | check tracemalloc MiB |
|---|---|---|---|---|---|---|---|
| 50,052 | 14.9 | 0.43 | 120.8 | 86.5 | 1.21 | 121.0 | 86.5 |
| 200,205 | 59.6 | 1.68 | 388.5 | 345.9 | 8.55 | 388.3 | 345.9 |
| 500,511 | 148.9 | 6.50 | 919.0 | 864.9 | 26.94 | 919.0 | 864.9 |
| 800,817 | 238.2 | 13.92 | 1453.6 | 1383.9 | 51.49 | 1453.5 | 1383.9 |

### After: the limit is 128 MiB

Command: `python scripts/bench.py all` (the same run as sections 1 to 3; `--records` defaults to
`50000,200000,400000`)

### Loading a baseline and running a whole check, at scale (fresh process each)

The trees are synthetic: the real scanner, encoder, MAC check and comparison run on a file system that
exists only as arithmetic, so that sizes up to the baseline size limit can be made without a million real files.
`load` is read, verify the MAC and parse; `check` is the whole command against an identical tree (no findings).
Peak working set is what the operating system reports for the process; tracemalloc is Python's own count.

| records | baseline MiB | load s | load peak working set MiB | load tracemalloc MiB | check s | check peak working set MiB | check tracemalloc MiB |
|---|---|---|---|---|---|---|---|
| 50,052 | 14.9 | 0.44 | 121.1 | 86.5 | 1.24 | 121.2 | 86.5 |
| 200,205 | 59.6 | 1.73 | 388.4 | 345.9 | 8.16 | 388.2 | 345.9 |
| 400,409 | 119.1 | 4.34 | 743.6 | 691.9 | 21.11 | 740.8 | 691.9 |

(MAX_FILES ceiling 1,000,000; default MAX_FILES 200,000)

### The decision

- **The peak is 6.1 to 6.5 times the file's size** from 60 MiB up (8.1 times at 15 MiB, where
  the interpreter's own 30 MiB weighs more), and a whole `check` peaks at the load figure: the parse is the high-water mark, and the scan result and the comparison fit
  inside what the parse needed. The largest size measured under the old limit, a 238 MiB baseline,
  needed 1,454 MiB (1.4 GiB).
- **The criterion.** `watch` re-reads and re-verifies the baseline every cycle, so the peak is
  paid again and again by a process that is meant to sit in the background on a laptop. I took
  "reasonable" to mean under 1 GiB for the largest baseline the tool accepts, which leaves an
  8 GiB laptop its working memory. At 256 MiB the figures above are over that line (1.4 GiB at
  238 MiB, measured); at 128 MiB the measured 119 MiB baseline peaked at 744 MiB, under it.
- **The result.** `MAX_BASELINE_BYTES` is **128 MiB**, both default and hard ceiling
  (`src/fim/core/limits.py`, PLAN.md D11 result note). This is a judgement about what a laptop
  should be asked to hold, not a technical limit; the reasoning and the figures are here so the
  owner can overrule it.
- **What 128 MiB holds.** About 300 bytes a record for short paths, so roughly 430,000 entries:
  more than twice the default `MAX_FILES` of 200,000. A configuration that raises `max_files`
  towards its ceiling of 1,000,000 can reach the byte limit first; `baseline` then refuses with a
  message and writes nothing. With the default `MAX_FILES`, the byte limit is reached only when
  the average path is longer than about 380 characters (non-ASCII characters cost six bytes each
  in the stored form).
- **A side effect, intended.** Limits are part of the policy digest and are stored in every
  baseline. A baseline written under the old 256 MiB limit is refused ("above its hard ceiling")
  and has to be made again. Nothing had been released.
- **Not done.** Reading the code, the load path holds the file's bytes, the payload slice, the
  buffer the MAC is computed over, the decoded text and the parsed JSON document next to the
  finished records. Freeing or streaming some of these would lower the peak without changing the
  limit. I did not change `baseline_codec.py` for it: it is the most security-critical module,
  and the owner's instruction was to lower the ceiling.

## 5. What these numbers do not say

- They are from one machine, one operating system and one Python version, on warm caches.
  Linux was not benchmarked (the Linux runs in WSL are test gates, not measurements).
- Real trees have longer paths, larger files and a different mix than 1 KiB files in 100-file
  directories; files of a few megabytes would shift cost from metadata to hashing, towards the
  figures of section 2.
- Network file systems were not measured.
- The first-run cost depends on the real-time protection product and its state.
