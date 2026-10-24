# dUP2 Patch Toolkit

Parse, inspect, export, and **apply** Search-and-Replace patch tables from
[dUP2](http://diablo2oo2.cjb.net/) ("diablo2oo2's universal patcher"), without
running the patcher's GUI against your target.

The toolkit ships two independent, byte-for-byte compatible implementations of
the same patch engine:

| File | Platform | Needs |
|------|----------|-------|
| **`dup2_parser.py`** | any (Python 3) | Python 3.6+ · `pefile` (only for `--dump`, auto-installed) |
| **`Invoke-Dup2Patch.ps1`** | Windows (PowerShell) | PowerShell 5.1+ |

Both read the same inputs and reproduce the DLL's `SearchAndReplace` behaviour
exactly:

- search **skips** positions whose `find_mask` byte is `01` (wildcard);
- on a match, `replace[]` is written only where `write_mask` byte is `00`;
- `flags`: `0xFFFFFFFF` = replace **all** matches, `1` = first only, `N` = Nth only.

---

## What it does

- **Parse** a patch table and print each unit's `find` / `replace` pattern in
  readable hex, with `??` for wildcards and `--` for "leave this byte".
- **Export** the table to JSON for diffing, review, or re-use.
- **Apply** the table to a target file — non-destructively by default.
- **Extract** (`--dump`, Python/Windows) the patch resources straight out of a
  packed dUP2 patcher `.exe` by launching it hidden, reading the
  `dup2patcher.dll` it drops into `%TEMP%`, and saving its `RT_RCDATA`
  sub-resources.

### Accepted inputs (auto-detected)

- a **raw resource blob** (binary, starts with `04 00 00 00`),
- a **hex-dump text file** (space/newline-separated hex pairs; other text is
  ignored, blank lines separate multiple blobs),
- a **JSON file** previously produced by `--json`.

---

## Install

No build step. Clone and run.

```sh
git clone https://github.com/<you>/<repo>.git
cd <repo>
```

`dup2_parser.py` needs only the Python standard library for everything except
`--dump`, which uses `pefile` and installs it on first use.

---

## Usage — Python (`dup2_parser.py`)

```sh
python3 dup2_parser.py <patchfile> [options]
python3 dup2_parser.py --dump <dup2_patcher.exe> [options]   # Windows only
```

### Modes

| Mode | What it does |
|------|--------------|
| *(default)* | parse and print the patch table |
| `--json` | dump the table as JSON to stdout |
| `--patch <targetfile>` | apply the table to `<targetfile>` |
| `--dump <patcher.exe>` | run a dUP2 patcher, extract its patch resources, then parse (Windows) |

### Options

| Flag | Meaning |
|------|---------|
| `--hex` / `--bin` | force raw-input interpretation (skip auto-detect) |
| `--raw` | also print the 4 raw arrays per unit (text mode) |
| `--json` | emit the parsed table as JSON |
| `--patch <file>` | apply the patch table to `<file>` |
| `-o <file>` | output path for `--patch` (default `<file>.patched`) |
| `--inplace` | patch `<file>` in place (writes a `<file>.bak` first) |
| `--dry-run` | with `--patch`: report what would change, write nothing |
| `--resource <n>` | if the table holds several resources, pick index `n` |
| `--all` | with `--dump`: keep the first sub-resource (the dUP2 info block) |
| `--wait <sec>` | with `--dump`: seconds to wait after launch (default `1`) |
| `-h`, `--help` | show help |

Flags accept one or two dashes (and `/flag` on Windows), in any position.

### Examples

```sh
# Inspect a table
python3 dup2_parser.py patch.txt
python3 dup2_parser.py patch.txt --raw

# Export to JSON
python3 dup2_parser.py patch.bin --json > table.json

# Apply (safe: writes target.exe.patched, original untouched)
python3 dup2_parser.py table.json --patch target.exe

# Preview without writing
python3 dup2_parser.py table.json --patch target.exe --dry-run

# Patch in place, keeping a .bak
python3 dup2_parser.py table.json --patch target.exe --inplace

# Pull the resources straight out of a packed patcher (Windows)
python3 dup2_parser.py --dump patch.exe --json > table.json
python3 dup2_parser.py --dump patch.exe --patch target.exe --resource 0
```

---

## Usage — PowerShell (`Invoke-Dup2Patch.ps1`)

Dot-source the script, then call the function:

```powershell
. .\Invoke-Dup2Patch.ps1

# Preview
Invoke-Dup2Patch -PatchFile Res_2.json -Target .\app.bin -DryRun

# Apply to a copy
Invoke-Dup2Patch -PatchFile Res_2.bin -Target .\app.bin -OutFile .\app.patched.bin

# Patch in place (writes app.bin.bak first)
Invoke-Dup2Patch -PatchFile Res_2.json -Target .\app.bin -InPlace
```

Or run it directly with the same parameters:

```powershell
.\Invoke-Dup2Patch.ps1 -PatchFile Res_2.json -Target .\app.bin -DryRun
```

| Parameter | Meaning |
|-----------|---------|
| `-PatchFile` | patch table (`.json`, raw `.bin`, or hex-dump `.txt`); auto-detected |
| `-Target` | file to patch |
| `-OutFile` | output path (default `<Target>.patched`) |
| `-InPlace` | overwrite target in place (writes a `.bak` first) |
| `-DryRun` | report only; write nothing |
| `-Resource <n>` | choose this 0-based resource index |

The PowerShell port does **not** implement `--dump`; extract resources with the
Python tool (or feed it a JSON/blob/hex table).

---

## Resource format (little-endian)

```
0x00  u32  arrays_per_unit (== 4; per-unit array-stride multiplier)
0x16  u32  offset of first unit (right after the NUL-terminated name)
0x22  str  target filename, NUL-terminated
then: units until trailing zero padding

unit = [u32 size][u32 flags] + 4 arrays of `size` bytes:
         pattern, find_mask (01 = wildcard), replace, write_mask (01 = leave byte)

flags: 0xFFFFFFFF = replace ALL matches; 1 = first only; N = Nth only
```

---

## Safety

Patching is **non-destructive by default**: the original is left alone and a
`.patched` copy is written. `--inplace` / `-InPlace` overwrite the target but
save a `.bak` first. Use `--dry-run` / `-DryRun` to see exactly which units
match and where before committing.

---

## Disclaimer

Provided for interoperability, research, and working with patch tables you are
entitled to use. You are responsible for how you use it.
