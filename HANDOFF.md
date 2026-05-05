# sysmon-parser — handoff

A Python CLI that parses Sysmon **Event ID 1 (Process Creation)** XML logs and emits JSON. Built as a focused tool for analysts who want to slice process-creation events down to the fields that matter, with first-class handling of base64-encoded PowerShell payloads.

Single commit so far: `2efbe10` on `main`.

## What we built

- **`parser.py`** — single-file CLI, ~80 lines, stdlib only (`xml.etree.ElementTree`, `base64`, `argparse`, `json`).
- **`samples/`** — four XML fixtures used to validate the parser end-to-end:
  - `event1.xml` — `whoami /all` from cmd.exe (benign, Medium integrity).
  - `event2.xml` — `cmd.exe` → `powershell.exe` running a `Get-Process` query (benign, Medium).
  - `event3.xml` — WINWORD.EXE spawning `powershell.exe -nop -w hidden -enc <base64>` (the realistic malicious case, High integrity, tagged with MITRE T1059.001).
  - `multi_events.xml` — the three above wrapped in a single `<Events>` root, used to test multi-event handling.
- **`CLAUDE.md`** — project context for future Claude Code sessions.
- **`.gitignore`** — excludes `__pycache__/` and `.claude/`.

### Extracted fields

`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`, plus a derived `DecodedCommandLine` whenever the `CommandLine` contains a PowerShell `-enc` / `-EncodedCommand` / `-ec` flag whose payload decodes successfully as base64 + UTF-16-LE.

### Filtering

Four flags, all optional:

| Flag | Semantics |
|------|-----------|
| `--image` | Case-insensitive substring on `Image` |
| `--user` | Exact match on `User` (e.g. `CORP\jdoe`) |
| `--integrity` | One of `High`, `Medium`, `Low`, `System` |
| `--cmdline` | Case-insensitive substring on `CommandLine` **and** `DecodedCommandLine`; repeatable to OR multiple substrings |

Flags combine with **AND** across; `--cmdline` ORs **within** when repeated. Passing any filter forces array output (even for one match) so downstream `jq` callers don't have to handle two shapes.

## How to use it

```bash
# Single file → JSON object
python3 parser.py samples/event1.xml

# Multi-event file → JSON array
python3 parser.py samples/multi_events.xml

# Find every PowerShell process
python3 parser.py samples/multi_events.xml --image powershell

# Catch encoded payloads referencing DownloadString — works because the
# decoded CommandLine is searched too
python3 parser.py samples/multi_events.xml --cmdline=DownloadString

# OR within --cmdline, AND across flags
python3 parser.py samples/multi_events.xml \
    --cmdline=DownloadString --cmdline=whoami \
    --integrity High

# Substrings starting with "-" need the = form (argparse footgun)
python3 parser.py samples/multi_events.xml --cmdline=-enc
```

Pipe into `jq` for further work — output is always valid JSON to stdout, errors and the argparse usage line go to stderr.

## What's left to do

Ordered roughly by likely value.

1. **Automated tests.** Verification so far is ad-hoc one-liners against the samples. A `pytest` suite covering: single vs multi dispatch, each filter independently, filter combinations, the OR-within / AND-across rules, the always-array-when-filtered rule, base64 decode of event3, and fail-soft on garbage payloads.
2. **Update stale section in `CLAUDE.md`.** The "To be filled in once code exists" block (entry point / build-lint-test commands / module layout) is now actually known and should be filled in or deleted.
3. **Streaming for large files.** `ET.parse` reads the whole document into memory. Switch to `iterparse` if anyone needs to process multi-GB Sysmon dumps.
4. **Support more Event IDs.** Right now everything assumes Event ID 1 fields. A real triage tool eventually wants Event 3 (network), 7 (image load), 11 (file create), etc. Probably `EVENT_DATA_FIELDS` becomes a per-event-id mapping.
5. **Quoted-arg-aware tokenization for `-enc` detection.** `CommandLine.split()` is naive — if a real Sysmon CommandLine ever quoted an `-enc` flag inside a string literal, we'd misread it. In practice Sysmon captures unquoted, so this is low priority.
6. **Hashes parsing.** `Hashes` is currently emitted as the raw `"SHA1=...,MD5=...,SHA256=...,IMPHASH=..."` string. Splitting into a sub-object would make it easier to filter on a specific hash.
7. **Filter on additional fields** (`--computer`, `--parent-image`) — same shape as the existing flags, only useful if hunters ask for it.
8. **Set git committer identity.** The initial commit went out as `charlottefoudy@Charlottes-MacBook-Air.local` because `git config user.email` isn't set. Worth fixing before pushing anywhere public.

Nothing in this list is blocking — the tool works as-is for its stated goal.

## Decisions and why

- **stdlib only.** No `pip install` step. Rolls onto any analyst workstation with a Python 3 install. Reconsider only if a feature genuinely needs `lxml` (e.g. for XPath 2.0).
- **Always-array output when any filter flag is passed.** The default no-filter rule is "1 event → object, ≥2 → array" (matches the original CLAUDE.md spec). When filtering, the post-filter count is unpredictable — making the shape stable so callers can `jq '.[] | ...'` without branching is more useful than consistency with the no-filter case.
- **Fail-soft base64 decode.** Real Sysmon feeds contain malformed payloads (truncation, custom obfuscation, stray bytes). One bad event aborting the entire run is the wrong default for an analyst tool. The cost is silent decode failures — acceptable because the raw `CommandLine` is still in the output and the analyst can see the `-enc` flag is there.
- **`DecodedCommandLine` omitted when absent, not null.** Keeps the existing 10-field shape stable for the (vast majority of) unencoded events, so consumers don't need to handle two key sets.
- **`-e` not treated as an encoded-command flag** even though PowerShell prefix-matching technically allows it. Ambiguous with `-ExecutionPolicy`, would generate false-positive decode attempts on every `-ExecutionPolicy Bypass` command line.
- **`--cmdline` uses `action='append'`, not `nargs='+'`.** `nargs='+'` is greedy and would eat the trailing positional path argument. `action='append'` is more typing for the user but unambiguous.
- **`--cmdline=-enc` instead of `--cmdline -enc`.** Standard argparse footgun: values starting with `-` look like flags. Documented in the `--help` text rather than worked around with custom parsing.
- **Filter rule asymmetry (`--cmdline` ORs within, others don't).** `--user` and `--integrity` are exact matches where ORing makes no semantic sense for a single value (and choices like `--integrity` are exclusive anyway). `--image` could plausibly support OR but no one asked for it; if requested, copy the `--cmdline` pattern.
- **Output ordering matches CLAUDE.md field order.** Not necessary technically — JSON object keys aren't ordered — but stable ordering keeps diffs and `jq` output predictable.

## Files

```
parser.py                # the CLI
CLAUDE.md                # project context for Claude Code
HANDOFF.md               # this file
.gitignore
samples/
  event1.xml             # whoami
  event2.xml             # cmd → powershell
  event3.xml             # WINWORD → encoded powershell
  multi_events.xml       # all three wrapped in <Events>
```
