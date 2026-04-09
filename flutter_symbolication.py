import json
import idaapi
import idc
import idautils

# =============================================================================
# CONFIG — edit these values before running
# =============================================================================
METADATA_FILE_PATH = r"C:\path\to\dump.dart"   # path to your reFlutter dump
DART_SNAPSHOT_BASE = None                       # set to e.g. 0xE8C0 to override
                                                # auto-detection; leave as None
                                                # to resolve from
                                                # _kDartIsolateSnapshotInstructions
# =============================================================================


def _ida_major():
    return idaapi.IDA_SDK_VERSION // 100


def _set_name(addr, name):
    flags = getattr(idaapi, "SN_FORCE", 0x800)
    idc.set_name(addr, name, flags)


def resolve_snapshot_base():
    """
    Try to find the Dart snapshot base automatically.
    Checks _kDartIsolateSnapshotInstructions first, then a set of common
    fallback symbol names used across different Flutter engine versions.
    Returns the address, or None if nothing is found.
    """
    candidates = [
        "_kDartIsolateSnapshotInstructions",
        "kDartIsolateSnapshotInstructions",
        "_kDartVmSnapshotInstructions",
        "kDartVmSnapshotInstructions",
    ]

    for sym in candidates:
        addr = idc.get_name_ea_simple(sym)
        if addr != idc.BADADDR:
            print(f"[*] Snapshot base resolved from '{sym}': {addr:#x}")
            return addr

    return None


def parse_reflutter_dump(content):
    content = content.strip()

    if content.startswith("["):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

    objs = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            break
    else:
        if objs:
            return objs

    fixed = "[" + content.replace("}{", "},{") + "]"
    return json.loads(fixed)


def sanitize_name(name):
    for ch in "<> ()[]:,*&/\\=+-{}":
        name = name.replace(ch, "_")
    while "__" in name:
        name = name.replace("__", "_")
    name = name.strip("_")
    if name and name[0].isdigit():
        name = "sym_" + name
    return name or "unknown"


def create_function(addr, name):
    if not idc.is_code(idc.get_full_flags(addr)):
        idaapi.create_insn(addr)
    if not idaapi.get_func(addr):
        idaapi.add_func(addr)
    _set_name(addr, name)


def run():
    snapshot_base = DART_SNAPSHOT_BASE

    if snapshot_base is None:
        snapshot_base = resolve_snapshot_base()

    if snapshot_base is None:
        print("[!] Could not resolve snapshot base automatically.")
        print("[!] Set DART_SNAPSHOT_BASE manually at the top of the script.")
        return

    print(f"[*] Dump file    : {METADATA_FILE_PATH}")
    print(f"[*] Snapshot base: {snapshot_base:#x}")
    print(f"[*] IDA version  : {_ida_major()}")

    with open(METADATA_FILE_PATH, "r", encoding="utf-8") as fh:
        content = fh.read()

    data = parse_reflutter_dump(content)
    print(f"[*] Entries found: {len(data)}")

    ok = 0
    skipped = 0

    for entry in data:
        method = entry.get("method_name") or entry.get("name")
        offset = entry.get("offset")

        if not method or not offset:
            skipped += 1
            continue

        try:
            addr = snapshot_base + int(offset, 16)
        except (ValueError, TypeError):
            skipped += 1
            continue

        cls = entry.get("class_name", "")
        fullname = f"{cls}.{method}" if cls else method
        name = sanitize_name(fullname)

        create_function(addr, name)

        comment_parts = []
        if cls:
            comment_parts.append(f"Class: {cls}")
        if entry.get("library_url"):
            comment_parts.append(f"Library: {entry['library_url']}")
        if entry.get("return_type"):
            comment_parts.append(f"Returns: {entry['return_type']}")
        if comment_parts:
            idc.set_cmt(addr, "\n".join(comment_parts), 0)

        ok += 1

    print(f"[+] Symbolicated : {ok} functions")
    if skipped:
        print(f"[!] Skipped      : {skipped} entries (missing method/offset)")
    print("[+] Done.")


run()