# sysmon-parser

A small Python CLI that parses Sysmon **Event ID 1 (Process Creation)** XML logs into JSON / JSONL / CSV. Built for analysts who want to slice process-creation events down to the fields that matter — with first-class handling of base64-encoded PowerShell payloads.

## What it does

- Extracts the 10 most-used Event ID 1 fields: `EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`.
- Detects PowerShell `-enc` / `-EncodedCommand` / `-ec` flags, base64-decodes the payload as UTF-16-LE, and surfaces it as a derived `DecodedCommandLine` field.
- Filters events by `Image`, `User`, `IntegrityLevel`, or substring of `CommandLine` (which also matches inside the decoded payload, so encoded PowerShell isn't a blind spot).
- Emits results as a JSON array, newline-delimited JSON, or CSV with a fixed schema.
- `--stats` mode for quick triage — total event count, unique processes, unique users, and an integrity-level breakdown.

## Install

No package install needed. Requirements:

- Python 3.7+
- Standard library only (no `pip install`, no virtualenv).

```bash
git clone https://github.com/cfoudysec/sysmon-parser.git
cd sysmon-parser
python3 parser.py samples/event1.xml
```

## Usage

```
python3 parser.py <path-to-xml> [filter flags] [--format {json,jsonl,csv}] [--stats]
```

### Basic — single file or multi-event file

The parser auto-detects whether the XML root is a single `<Event>` or a wrapper element containing multiple events.

```bash
python3 parser.py samples/event1.xml          # one event
python3 parser.py samples/multi_events.xml    # three events
```

### Filtering

| Flag | Match |
|------|-------|
| `--image SUBSTRING` | case-insensitive substring on `Image` |
| `--user VALUE` | exact match on `User` (e.g. `CORP\jdoe`) |
| `--integrity {High,Medium,Low,System}` | exact match on `IntegrityLevel` |
| `--cmdline SUBSTRING` | case-insensitive substring on `CommandLine` *and* `DecodedCommandLine`; repeatable |

Filters combine with **AND** across different flags. `--cmdline` repeated combines its own values with **OR**.

```bash
# All powershell.exe events
python3 parser.py samples/multi_events.xml --image powershell

# All High-integrity events run as CORP\mlopez
python3 parser.py samples/multi_events.xml --user 'CORP\mlopez' --integrity High

# Find encoded payloads referencing DownloadString — works even though
# the literal string is hidden inside base64
python3 parser.py samples/multi_events.xml --cmdline=DownloadString

# OR: match either of two suspicious substrings
python3 parser.py samples/multi_events.xml --cmdline=DownloadString --cmdline=Invoke-Expression
```

> **Note:** for `--cmdline` values that start with `-` (e.g. `-enc`), use the `=` form: `--cmdline=-enc`. Without it, argparse will treat the value as another flag.

### Output formats

```bash
python3 parser.py samples/multi_events.xml                      # JSON array (default)
python3 parser.py samples/multi_events.xml --format jsonl       # one JSON object per line
python3 parser.py samples/multi_events.xml --format csv         # CSV with header
```

CSV includes a fixed 11-column schema: the 10 standard fields plus `DecodedCommandLine` (column is empty when the event had no encoded payload). `csv.writer` handles quoting for embedded commas and double-quotes.

### Triage stats

```bash
python3 parser.py samples/multi_events.xml --stats
```

```
Total events: 3

Unique Images: 2
  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  C:\Windows\System32\whoami.exe

Unique Users: 3
  CORP\asmith
  CORP\jdoe
  CORP\mlopez

Events by IntegrityLevel:
  Medium: 2
  High: 1
```

Filters apply *before* stats, so `--stats --integrity High` summarizes only the High-integrity subset. `--format` is ignored in stats mode.

## Sample data

`samples/` contains four XML fixtures:

- `event1.xml` — `whoami /all` from `cmd.exe` (benign)
- `event2.xml` — `cmd.exe` → `powershell.exe` running `Get-Process` (benign)
- `event3.xml` — Word document → `powershell.exe -nop -w hidden -enc <base64>` (the realistic malicious case; tagged with MITRE T1059.001)
- `multi_events.xml` — all three wrapped in a single `<Events>` root

## Limitations / known gaps

- Only Event ID 1 is supported.
- Whole-document XML parsing — fine for typical Sysmon exports, but for multi-GB feeds you'd want `iterparse`.
- `Hashes` is emitted as the raw `SHA1=…,MD5=…` string rather than split into a sub-object.
- No automated test suite yet.

See [HANDOFF.md](HANDOFF.md) for the full backlog and the design decisions behind each one.

## Files

```
parser.py        # the CLI
samples/         # XML fixtures
README.md        # this file
HANDOFF.md       # design decisions, backlog
CLAUDE.md        # context for Claude Code sessions extending the project
```
