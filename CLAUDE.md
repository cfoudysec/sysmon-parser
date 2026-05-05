# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Python tool that parses Sysmon (Microsoft System Monitor) XML event logs and extracts fields from **Event ID 1 (Process Creation)** events into JSON.

Single-file CLI: `parser.py`. Stdlib only — no `pip install`, no virtualenv. Run as `python3 parser.py <path> [flags]`.

Sample fixtures live in `samples/`. End-to-end verification has been ad-hoc Bash one-liners against those fixtures; there is no `pytest` suite yet.

## Fields extracted from Event ID 1

`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`, plus a derived `DecodedCommandLine` (only present when `CommandLine` contains a PowerShell `-enc`/`-EncodedCommand`/`-ec` flag whose payload decodes as base64 + UTF-16-LE). Output key order matches this list.

## Architectural decisions

### XML parsing — `xml.etree.ElementTree`

Whole-document `ET.parse` into memory, namespace-aware (Sysmon's namespace is `http://schemas.microsoft.com/win/2004/08/events/event`, bound to prefix `e` in queries). Stdlib choice was deliberate: stays portable, runs on any analyst workstation. **If multi-GB feeds become a requirement, switch to `iterparse`** — don't reach for `lxml` unless XPath 2.0 is genuinely needed.

The parser handles two input shapes via root-tag dispatch in `main()`:
- Root is `<Event>` (single-event file) → wrap as `[root]`.
- Anything else (e.g. `<Events>` wrapper) → `findall("e:Event", NS)`.

When extending field extraction, modify `EVENT_DATA_FIELDS` and the `ordered` list in `parse_event` — they govern which `<Data Name="...">` elements are pulled from `<EventData>` and the resulting JSON key order.

### Output format — `--format` flag, three modes

Single output flag with three values, all multi-record:

| `--format` | Shape |
|------------|-------|
| `json` (default) | JSON array, indented; empty result is `[]` |
| `jsonl` | One JSON object per line (newline-delimited), no outer wrapping; empty result is no output |
| `csv` | Header row followed by one data row per event; empty result is just the header |

All three are inherently array-shaped — there is **no** "single event → object" special case. (Earlier versions returned an object for unfiltered single-event input; that behavior was dropped when `--format` landed because the inconsistency made piping awkward.) When extending output, keep this invariant: every format must be safe to consume by a streaming/multi-record reader.

Errors and `argparse` usage go to stderr; stdout is always valid output for the chosen format.

**CSV column set is fixed** at the 10 standard fields plus `DecodedCommandLine`, in the order defined by `CSV_FIELDS` in `parser.py`. The `DecodedCommandLine` column is always present and empty when the event had no encoded payload — CSV needs a stable schema.

**JSON / JSONL behavior for `DecodedCommandLine`:** the key is **omitted** (not `null`) when no `-enc` flag is detected, so unencoded events keep their original 10-field shape. Decoding is **fail-soft**: malformed base64 or non-UTF-16-LE bytes produce no `DecodedCommandLine`, never an exception. Real Sysmon feeds are noisy and one bad event must not abort the run.

### Filter flags and how they combine

| Flag | Field | Match |
|------|-------|-------|
| `--image` | `Image` | case-insensitive substring |
| `--user` | `User` | exact |
| `--integrity` | `IntegrityLevel` | exact, restricted to `High`/`Medium`/`Low`/`System` via argparse `choices` |
| `--cmdline` | `CommandLine` and `DecodedCommandLine` | case-insensitive substring; **repeatable** (`action='append'`) |

**Combination rules:**
- Across different flags → **AND**.
- Within `--cmdline` (when repeated) → **OR**.
- `--cmdline` against an event searches both `CommandLine` and `DecodedCommandLine`, so encoded payloads are findable transparently (`--cmdline=DownloadString` matches event3 even though the literal string is only present after base64-decoding the payload).

**Conventions when adding new filters:**
- Match the existing flag style. Substring filters case-insensitive; exact filters case-sensitive (matches Sysmon's casing). Use argparse `choices` for closed enumerations.
- Add the check to `matches()` and update the `filtering` predicate in `main()` so an empty value doesn't accidentally count as "filter active."
- Don't introduce greedy `nargs='+'` flags — they swallow the positional path argument. Use `action='append'` instead.
- Document the `--flag=-value` form in help text for any flag that might receive values starting with `-` (argparse footgun).

### `--stats` mode

> This stats feature is for quick triage to understand what's in a file before deep analysis.

`--stats` short-circuits event output and prints a plain-text summary: total event count, sorted list of unique `Image` values, sorted list of unique `User` values, and a `Counter`-driven `IntegrityLevel` breakdown ordered by frequency. Filters apply *before* stats, so `--stats --integrity High` summarizes only the High-integrity subset. `--format` is ignored under `--stats` (plain text is the only output mode for this feature; if structured stats become needed, add `--stats-format json` rather than overloading `--format`).

### Out of scope (deliberate)

- Event IDs other than 1.
- Splitting `Hashes` into a sub-object (currently emitted as the raw `"SHA1=...,MD5=..."` string).
- `-e` as a PowerShell encoded-command flag — prefix-ambiguous with `-ExecutionPolicy`, would cause false-positive decode attempts.
