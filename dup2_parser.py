#!/usr/bin/env python3
r"""
dup2_parser.py - parse, export, apply, and EXTRACT dUP2 ("diablo2oo2's
                 universal patcher") Search-and-Replace patch resources.

USAGE
    python3 dup2_parser.py <patchfile> [options]
    python3 dup2_parser.py --dump <dup2_patcher.exe> [options]     (Windows)

<patchfile> is the patch table, in any of:
  * a raw resource blob (binary, starts with 04 00 00 00),
  * a text hex dump (space/newline hex pairs; other text ignored; blank-line-
    separated blobs each parsed),
  * a JSON file previously produced by --json.
Type is auto-detected; force the raw/hex kind with --hex / --bin.

MODES
    (default)              parse and print the patch table
    --json                 dump the table as JSON to stdout (redirect: > out.json)
    --patch <targetfile>   APPLY the table to <targetfile> (see below)
    --dump <patcher.exe>   run a dUP2 patcher, extract the patch resources it
                           drops, save them, then parse them (Windows only)

OPTIONS
    --hex / --bin     force raw-input interpretation (skip auto-detect)
    --raw             also print the 4 raw arrays per unit (text mode)
    --json            emit the parsed table as JSON
    --patch <file>    apply the patch table to <file>
    -o <file>         output path for --patch (default: <file>.patched)
    --inplace         patch <file> in place (a <file>.bak backup is written first)
    --dry-run         with --patch: report what would change, write nothing
    --resource <n>    if the table holds several resources, pick index n
    --dump <exe>      extract-and-parse mode (see --dump MODE below)
    --all             with --dump: keep the FIRST sub-resource (default: skip it)
    --wait <sec>      with --dump: seconds to wait after launch (default: 1)
    -h, --help        show this help
Flags accept one or two dashes (and /flag on Windows), in any position.

--dump MODE (Windows, needs pefile - auto-installed)
    1. launches <patcher.exe>
    2. waits (default 1s) while it decompresses dup2patcher.dll into %TEMP%
    3. reads its RT_RCDATA sub-resources, ordered 1 -> END
    4. SKIPS the first (res_1 = dUP2 info block), saves the rest into
       .\export\  as  res_2, res_3, ...   (use --all to keep res_1)
    5. closes the patcher
    6. parses the saved resources -> normal print / --json / --patch all apply
    e.g.  dup2_parser.py --dump patch.exe
          dup2_parser.py --dump patch.exe --raw
          dup2_parser.py --dump patch.exe --json > table.json
          dup2_parser.py --dump patch.exe --patch target.exe --resource 0

RESOURCE FORMAT (little-endian)
    0x00  u32  arrays_per_unit (==4; per-unit array-stride multiplier)
    0x16  u32  offset of first unit (right after the NUL-terminated name)
    0x22  str  target filename, NUL-terminated
    then: units until trailing zero padding
    unit = [u32 size][u32 flags] + 4 arrays of `size` bytes:
       pattern, find_mask (01=wildcard), replace, write_mask (01=leave byte)
    flags: 0xFFFFFFFF = replace ALL matches; 1 = first only; N = Nth only.
"""
import struct, sys, re, os, json

# ---------- loading the patch table ----------

def load_blobs_from_text(text):
    blobs, cur = [], []
    for ln in text.splitlines():
        s = ln.strip()
        if s and re.fullmatch(r'([0-9A-Fa-f]{2}\s*)+', s):
            cur += s.split()
        elif cur:
            blobs.append(bytes(int(b, 16) for b in cur)); cur = []
    if cur:
        blobs.append(bytes(int(b, 16) for b in cur))
    return blobs

def looks_like_text(data):
    return b'\x00' not in data

def describe_flags(flags):
    if flags == 0xFFFFFFFF:
        return "replace ALL matches"
    if flags == 1:
        return "replace 1st match only"
    return f"replace match #{flags} only"

def parse_blob(d):
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    apu = u32(0)
    if apu < 1 or apu > 16:
        apu = 4
    name_end = d.index(0, 0x22)
    name = d[0x22:name_end].decode('ascii', 'replace')
    off, units = name_end + 1, []
    while off + 8 <= len(d):
        size, flags = u32(off), u32(off + 4)
        stride = 8 + apu * size
        if size == 0 or size > 0x1000 or off + stride > len(d):
            break
        base = off + 8
        arrs = [d[base + i*size: base + (i+1)*size] for i in range(apu)]
        units.append({"offset": off, "size": size, "flags": flags,
                      "pattern": arrs[0], "find_mask": arrs[1],
                      "replace": arrs[2], "write_mask": arrs[3]})
        off += stride
    return {"target": name, "arrays_per_unit": apu, "units": units,
            "consumed": off, "tail": d[off:]}

def load_table(path, force=None):
    """Return list of resource dicts (units carry bytes), + the input kind."""
    data = open(path, 'rb').read()
    # JSON?
    txt = None
    if force is None:
        try:
            txt = data.decode('utf-8')
            if txt.lstrip()[:1] in '{[':
                j = json.loads(txt)
                res = []
                for r in j.get("resources", []):
                    us = []
                    for u in r.get("units", []):
                        unhex = lambda s: bytes.fromhex(s.replace(' ', ''))
                        us.append({"offset": u.get("offset", 0), "size": u["size"],
                                   "flags": int(u["flags"]),
                                   "pattern": unhex(u["pattern"]),
                                   "find_mask": unhex(u["find_mask"]),
                                   "replace": unhex(u["replace"]),
                                   "write_mask": unhex(u["write_mask"])})
                    res.append({"target": r.get("target", "?"),
                                "arrays_per_unit": r.get("arrays_per_unit", 4),
                                "units": us, "consumed": None, "tail": b""})
                return res, "json"
        except (UnicodeDecodeError, ValueError):
            pass
    mode = force or ('hex' if looks_like_text(data) else 'bin')
    blobs = load_blobs_from_text(data.decode('latin1')) if mode == 'hex' else [data]
    return [parse_blob(b) for b in blobs], mode

# ---------- extract-and-parse (--dump): run a dUP2 patcher, grab resources ----------

def _extract_resources_from_patcher(exe, skip_first=True, wait=1.0):
    """Launch patcher, grab dropped dup2patcher.dll's RT_RCDATA sub-resources.
    Saves them to .\\export\\ and returns a list of parsed resource dicts."""
    import time, glob, subprocess, tempfile
    try:
        import pefile
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pefile", "-q"])
        import pefile

    DLL_NAME = "dup2patcher.dll"
    OUT_DIR  = os.path.join(os.getcwd(), "export")

    exe = os.path.abspath(exe)
    if not os.path.isfile(exe):
        raise FileNotFoundError(exe)

    def find_dropped_dll(since):
        dirs = {tempfile.gettempdir(), os.environ.get("TEMP", ""),
                os.environ.get("TMP", "")}
        cand = []
        for dd in filter(None, dirs):
            p = os.path.join(dd, DLL_NAME)
            if os.path.isfile(p):
                cand.append(p)
            for f in glob.glob(os.path.join(dd, "*.dll")):
                try:
                    if os.path.getmtime(f) >= since - 2:
                        cand.append(f)
                except OSError:
                    pass
        if not cand:
            return None
        exact = [c for c in cand if os.path.basename(c).lower() == DLL_NAME]
        return max(exact or cand, key=os.path.getmtime)

    def close_patcher(proc):
        print("[*] Closing patcher...", file=sys.stderr)
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:
            pass
        subprocess.run(["taskkill", "/F", "/IM", os.path.basename(exe)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    SW_HIDE, SW_MINIMIZE = 0, 6
    HIDE_MODE = SW_HIDE               # <- set to SW_MINIMIZE to minimize instead

    def hide_pid_windows(pid, mode=HIDE_MODE):
        """Force every top-level window owned by pid to hide/minimize.
        dUP2's GUI shows itself at startup and ignores the STARTUPINFO hint,
        so we hide it directly once it appears."""
        if os.name != "nt":
            return 0
        import ctypes
        user32 = ctypes.windll.user32
        done = [0]
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def cb(hwnd, _):
            wpid = ctypes.c_ulong(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
            if wpid.value == pid:
                user32.ShowWindow(hwnd, mode)
                done[0] += 1
            return True
        user32.EnumWindows(WNDENUMPROC(cb), 0)
        return done[0]

    # the STARTUPINFO hint still helps apps that *do* respect it
    popen_kw = {"cwd": os.path.dirname(exe)}
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = HIDE_MODE
        popen_kw["startupinfo"] = si

    started = time.time()
    print("[*] Launching patcher (hidden):", exe, file=sys.stderr)
    proc = subprocess.Popen([exe], **popen_kw)

    # keep hiding the window(s) as they appear, for at least `wait` seconds
    deadline = started + max(wait, 1.5)
    while time.time() < deadline:
        hide_pid_windows(proc.pid)
        time.sleep(0.08)

    dll = find_dropped_dll(started)
    if not dll:
        close_patcher(proc)
        raise RuntimeError("dup2patcher.dll not found in TEMP (try --wait 2)")
    print("[*] Found dropped DLL:", dll, file=sys.stderr)

    try:
        pe = pefile.PE(dll, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        rc = next((e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries
                   if pefile.RESOURCE_TYPE.get(e.struct.Id) == 'RT_RCDATA'), None)
        if rc is None:
            raise RuntimeError("no RT_RCDATA in dropped DLL")

        subs = sorted(rc.directory.entries,
                      key=lambda e: (e.struct.Id if e.name is None else 1 << 31,
                                     str(e.name)))
        img = pe.get_memory_mapped_image()
        os.makedirs(OUT_DIR, exist_ok=True)

        resources = []
        for i, sub in enumerate(subs, start=1):
            ident = sub.struct.Id if sub.name is None else sub.name
            if skip_first and i == 1:
                print(f"[-] skipped res_{i} (id={ident}, dUP2 info block)", file=sys.stderr)
                continue
            lang = sub.directory.entries[0]
            off, size = lang.data.struct.OffsetToData, lang.data.struct.Size
            blob = img[off:off + size]
            out = os.path.join(OUT_DIR, f"res_{i}")
            with open(out, "wb") as fh:
                fh.write(blob)
            print(f"[+] res_{i}  (id={ident}, {size} bytes)  -> {out}", file=sys.stderr)
            try:
                resources.append(parse_blob(blob))
            except Exception:
                resources.append({"target": f"res_{i}", "arrays_per_unit": 4,
                                  "units": [], "consumed": 0, "tail": blob})
        pe.close()
        print(f"[*] Extracted {len(resources)} resource(s) into {OUT_DIR}", file=sys.stderr)
        return resources
    finally:
        close_patcher(proc)

# ---------- rendering ----------

def render(pattern, find_mask, replace, wr_mask):
    find = ' '.join('??' if m == 1 else f'{b:02X}' for b, m in zip(pattern, find_mask))
    repl = ' '.join('--' if m == 1 else f'{b:02X}' for b, m in zip(replace, wr_mask))
    return find, repl

# ---------- the patch engine (faithful to the DLL's SearchAndReplace) ----------

def find_matches(buf, pattern, fmask):
    """Offsets where pattern matches buf, ignoring positions whose find_mask==1."""
    n = len(pattern)
    best = (0, -1); cur = None            # longest run of significant bytes = anchor
    for i in range(n + 1):
        sig = i < n and fmask[i] == 0
        if sig and cur is None:
            cur = i
        if (not sig) and cur is not None:
            if (i - 1 - cur) > (best[1] - best[0]):
                best = (cur, i - 1)
            cur = None
    a0, a1 = best
    anchor = bytes(pattern[a0:a1 + 1]) if a1 >= a0 else b""
    sig_idx = [i for i in range(n) if fmask[i] == 0]
    out, start = [], 0
    while True:
        if anchor:
            j = buf.find(anchor, start)
            if j < 0:
                break
            off = j - a0; start = j + 1
        else:
            off = start; start += 1
            if off + n > len(buf):
                break
        if off < 0 or off + n > len(buf):
            continue
        if all(buf[off + i] == pattern[i] for i in sig_idx):
            out.append(off)
    return out

def apply_unit(buf, u):
    """Apply one unit to bytearray buf. Returns (match_offsets, applied_offsets)."""
    matches = find_matches(buf, u["pattern"], u["find_mask"])
    flags = u["flags"]
    if flags == 0xFFFFFFFF:
        targets = matches
    elif 1 <= flags <= len(matches):
        targets = [matches[flags - 1]]       # the Nth occurrence only
    else:
        targets = []
    size, rep, wm = u["size"], u["replace"], u["write_mask"]
    for off in targets:
        for i in range(size):
            if wm[i] != 1:
                buf[off + i] = rep[i]
    return matches, targets

# ---------- CLI ----------

FLAG_OPTS  = {'hex', 'bin', 'raw', 'json', 'h', 'help', '?', 'inplace',
              'dryrun', 'dry-run', 'all'}
VALUE_OPTS = {'patch', 'o', 'out', 'output', 'resource', 'dump', 'wait'}

def parse_args(raw):
    opts, kv, positional = set(), {}, []
    i = 0
    while i < len(raw):
        a = raw[i]
        name = a.lstrip('-/').lower() if a[:1] in '-/' else None
        is_opt = a.startswith('-') or (a.startswith('/') and name in (FLAG_OPTS | VALUE_OPTS) and '/' not in name)
        if is_opt and name in VALUE_OPTS:
            kv[name] = raw[i + 1] if i + 1 < len(raw) else None; i += 2; continue
        elif is_opt:
            opts.add(name)
        else:
            positional.append(a)
        i += 1
    return opts, kv, positional

def hx(a):
    return ' '.join(f'{b:02X}' for b in a)

def print_table(resources, show_raw):
    for bi, r in enumerate(resources):
        units = r["units"]
        if r.get("consumed") is not None:
            clean = all(b == 0 for b in r["tail"])
            warn = '' if clean else '   *** tail NOT all-zero: wrong format? ***'
            print(f"\n== resource {bi}: target={r['target']!r}  arrays/unit={r['arrays_per_unit']}  units={len(units)} ==")
            print(f"   consumed 0x00..0x{r['consumed']:X}; {len(r['tail'])} trailing bytes, padding_ok={clean}{warn}")
        else:
            print(f"\n== resource {bi}: target={r['target']!r}  units={len(units)} (from JSON) ==")
        for idx, u in enumerate(units):
            find, repl = render(u["pattern"], u["find_mask"], u["replace"], u["write_mask"])
            print(f"   -- unit {idx} @0x{u['offset']:04X} len={u['size']}  "
                  f"flags=0x{u['flags']:08X} ({describe_flags(u['flags'])})")
            print(f"        find   : {find}")
            print(f"        replace: {repl}")
            if show_raw:
                print(f"        pattern  : {hx(u['pattern'])}")
                print(f"        find_mask: {hx(u['find_mask'])}")
                print(f"        replace  : {hx(u['replace'])}")
                print(f"        wr_mask  : {hx(u['write_mask'])}")

def table_json(resources):
    out = []
    for bi, r in enumerate(resources):
        rec = {"index": bi, "target": r["target"],
               "arrays_per_unit": r.get("arrays_per_unit", 4),
               "unit_count": len(r["units"]), "units": []}
        if r.get("consumed") is not None:
            rec["consumed_bytes"] = r["consumed"]
            rec["trailing_bytes"] = len(r["tail"])
            rec["padding_ok"] = all(b == 0 for b in r["tail"])
        for idx, u in enumerate(r["units"]):
            find, repl = render(u["pattern"], u["find_mask"], u["replace"], u["write_mask"])
            rec["units"].append({
                "index": idx, "offset": u["offset"], "offset_hex": f"0x{u['offset']:04X}",
                "size": u["size"], "flags": u["flags"], "flags_hex": f"0x{u['flags']:08X}",
                "flags_meaning": describe_flags(u["flags"]),
                "pattern": hx(u["pattern"]), "find_mask": hx(u["find_mask"]),
                "replace": hx(u["replace"]), "write_mask": hx(u["write_mask"]),
                "find_render": find, "replace_render": repl})
        out.append(rec)
    return {"resources": out}

def do_patch(resources, target, out_path, inplace, dry_run, res_idx):
    if not os.path.isfile(target):
        print(f"error: target file not found: {target}", file=sys.stderr); return 2
    if len(resources) == 1 or res_idx is None:
        r = resources[res_idx if res_idx is not None else 0]
        if len(resources) > 1 and res_idx is None:
            base = os.path.basename(target).lower()
            for cand in resources:
                if cand["target"].lower() == base:
                    r = cand; break
            else:
                print(f"note: {len(resources)} resources in table; using #0. Use --resource N to choose.", file=sys.stderr)
    else:
        if res_idx < 0 or res_idx >= len(resources):
            print(f"error: --resource {res_idx} out of range (0..{len(resources)-1})", file=sys.stderr); return 2
        r = resources[res_idx]

    tgt_name = os.path.basename(target)
    if r["target"] and r["target"].lower() != tgt_name.lower():
        print(f"note: table targets {r['target']!r}, patching {tgt_name!r} anyway.", file=sys.stderr)

    buf = bytearray(open(target, 'rb').read())
    total_applied = 0
    print(f"patching {target} ({len(buf):,} bytes) with {len(r['units'])} unit(s):")
    for idx, u in enumerate(r["units"]):
        matches, applied = apply_unit(buf, u)
        total_applied += len(applied)
        meaning = describe_flags(u["flags"])
        at = ' '.join(f'0x{o:X}' for o in applied) or '-'
        note = ""
        if not matches:
            note = "  [PATTERN NOT FOUND]"
        elif u["flags"] not in (0xFFFFFFFF,) and not (1 <= u["flags"] <= len(matches)):
            note = f"  [wanted match #{u['flags']}, only {len(matches)} found]"
        print(f"  unit {idx:2d} len={u['size']:3d} [{meaning}]: "
              f"{len(matches)} match(es), {len(applied)} applied @ {at}{note}")

    if dry_run:
        print(f"\n[dry-run] {total_applied} replacement(s) would be written; no file changed.")
        return 0
    if total_applied == 0:
        print("\nnothing matched; no output written.")
        return 1
    if inplace:
        bak = target + ".bak"
        if not os.path.exists(bak):
            open(bak, 'wb').write(open(target, 'rb').read())
        open(target, 'wb').write(buf)
        print(f"\nwrote {total_applied} replacement(s) in place: {target}  (backup: {bak})")
    else:
        dst = out_path or (target + ".patched")
        open(dst, 'wb').write(buf)
        print(f"\nwrote {total_applied} replacement(s) -> {dst}  (original untouched)")
    return 0

def main(argv):
    raw = list(argv[1:])
    opts, kv, positional = parse_args(raw)
    if not raw or (opts & {'h', 'help', '?'}):
        print(__doc__); return 0 if raw else 2

    # ---- source the resources: either --dump <exe>, or a <patchfile> ----
    if 'dump' in kv:
        if not kv['dump']:
            print("error: --dump needs a patcher .exe", file=sys.stderr); return 2
        wait = 1.0
        if kv.get('wait') is not None:
            try: wait = float(kv['wait'])
            except ValueError: pass
        try:
            resources = _extract_resources_from_patcher(
                kv['dump'], skip_first=('all' not in opts), wait=wait)
        except Exception as e:
            print(f"error: --dump failed: {e}", file=sys.stderr); return 1
    else:
        if not positional:
            print("error: no patch file given (see --help)", file=sys.stderr); return 2
        path = positional[0]
        if not os.path.isfile(path):
            print(f"error: no such file: {path}", file=sys.stderr); return 2
        force = 'hex' if 'hex' in opts else ('bin' if 'bin' in opts else None)
        try:
            resources, kind = load_table(path, force)
        except Exception as e:
            print(f"error: could not read patch table: {e}", file=sys.stderr); return 1

    if not resources:
        print("error: no patch data found", file=sys.stderr); return 1

    # ---- then do whatever was asked with them ----
    if 'patch' in kv:
        res_idx = int(kv['resource']) if kv.get('resource') is not None else None
        return do_patch(resources, kv['patch'],
                        kv.get('o') or kv.get('out') or kv.get('output'),
                        'inplace' in opts, ('dryrun' in opts or 'dry-run' in opts),
                        res_idx)

    if 'json' in opts:
        print(json.dumps(table_json(resources), indent=2)); return 0
    print_table(resources, 'raw' in opts)
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        try: sys.stdout.close()
        except Exception: pass
        os._exit(0)
