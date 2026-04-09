# flutter_symbolicate

An IDA Pro script to symbolicate Flutter/Dart snapshots using a [reFlutter](https://github.com/Impact-I/reFlutter) `dump.dart` file.

## Requirements

- IDA Pro 7.x or 8.x
- A reFlutter `dump.dart` (or `dump.json`) from your target app

## Setup

Open `flutter_symbolicate.py` and edit the two variables at the top:

```python
METADATA_FILE_PATH = r"C:\path\to\dump.dart"   # path to your reFlutter dump
DART_SNAPSHOT_BASE = None                       # None = auto-detect
```

**Snapshot base auto-detection**

When `DART_SNAPSHOT_BASE` is set to `None` (the default), the script will automatically resolve the base address by looking for these symbols in the loaded binary, in order:

- `_kDartIsolateSnapshotInstructions`
- `kDartIsolateSnapshotInstructions`
- `_kDartVmSnapshotInstructions`
- `kDartVmSnapshotInstructions`

If one is found, its address is used as the snapshot base. If none are found, the script will print an error and exit — in that case, set `DART_SNAPSHOT_BASE` to the correct address manually (e.g. `0xE8C0`).

## Usage

1. Open your target binary in IDA Pro and wait for auto-analysis to finish.
2. Set `METADATA_FILE_PATH` in the script.
3. Run via **File → Script file...** and select `flutter_symbolicate.py`.

Output is printed to the IDA console:

```
[*] Snapshot base resolved from '_kDartIsolateSnapshotInstructions': 0xe8c0
[*] Dump file    : C:\path\to\dump.dart
[*] Snapshot base: 0xe8c0
[*] IDA version  : 7
[*] Entries found: 1234
[+] Symbolicated : 1230 functions
[!] Skipped      : 4 entries (missing method/offset)
[+] Done.
```

## Dump format support

The script handles all three formats that reFlutter may produce:

- Newline-separated JSON objects (one per line)
- A JSON array (`[{...},{...}]`)
- Concatenated JSON objects (`{...}{...}`)

## Notes

- Each function is created and named in IDA using the full `ClassName.methodName` format.
- A comment is added to each function with the class name, library URL, and return type where available.
- Names are sanitized to strip characters IDA does not allow in symbol names.

## License

MIT
