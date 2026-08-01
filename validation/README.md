# Validation — golden-verdict ground truth

Unit tests (`pytest`) prove ARGUS's *logic*. This proves it agrees with *reality*:
you point it at samples whose correct answer you already know, and `selftest`
checks ARGUS produces that answer.

```bash
python run.py selftest                       # runs validation/manifest.json
python run.py selftest --manifest other.json
```
Exit code is non-zero if any case fails, so it can gate CI.

## Set it up

1. Copy `manifest.example.json` → `manifest.json`.
2. Drop ground-truth data under `validation/` (gitignored — it's malware/large):
   - `validation/samples/` — sample files
   - `validation/images/` — memory dumps
3. Edit the cases. Paths are relative to the manifest.

## Case types (none execute a sample)

| type | runs | good for |
|------|------|----------|
| `static` | static analysis + YARA on a file | EICAR, clean binaries, packed samples, rule hits |
| `memscan` | Volatility3 cross-view on a dump | a **known-rootkit memory image** (safest end-to-end test) |
| `findings` | reads a completed run's `findings.json` | validating a detonation verdict you already produced |

## Expectations

`verdict`, `verdict_not`, `yara_any` (bool), `yara_rule` (name), `packed` (bool),
`signal` (name), `hidden_process` (bool), `hidden_driver` (bool), `severity` (level).

## Where to get ground truth

- **EICAR** — the standard AV test string (eicar.org). Must come back benign.
- **Clean binaries** — `C:\Windows\System32\*.exe`. Must come back benign (no FPs).
- **Known-rootkit memory images** — the **Volatility Foundation sample images**
  (github.com/volatilityfoundation → sample images; the malware-cookbook images)
  ship with documented hidden processes/drivers. Point a `memscan` case at one and
  assert `hidden_process: true` — this validates the memory layer end-to-end with a
  known answer and **zero risk**.
- **MalwareBazaar** — hash-verified samples with known families for `static`/`findings`
  cases (VM only).

Start with the EICAR + clean-binary + one Volatility-image cases — that trio alone
validates the benign path, the false-positive path, and the rootkit-detection path.
