# file-integrity-monitor (fim)

A defensive file integrity monitor for home labs and endpoints you own. `fim` records the state
of configured paths into an HMAC-protected baseline and later reports what changed. It only reads
the files it monitors.

**Status: work in progress (Phase 1 of 6).** Only `fim --version` exists. There are no feature
claims, benchmarks or example output yet; those are added when the code and the measurements exist.
The design is in [PLAN.md](PLAN.md) and the working rules are in [CLAUDE.md](CLAUDE.md).

## Development

```
uv venv --python 3.13 .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
python scripts/gate.py            # fast gate
python scripts/gate.py --full     # everything, as CI runs it
```

## License

MIT, see [LICENSE](LICENSE).
