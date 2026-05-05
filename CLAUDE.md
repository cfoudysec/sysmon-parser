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

### Output format — JSON to stdout

Two shape rules layered together:

1. **No filter flags passed:** 1 event → JSON object, ≥2 events → JSON array. Preserves the original spec (single events shouldn't need array unwrapping for the trivial case).
2. **Any filter flag passed:** always a JSON array, even if exactly one event matches and even if the result is empty (`[]`). Stable shape for `jq` pipelines is more useful than consistency with the no-filter case.

Errors and `argparse` usage go to stderr; stdout is always valid JSON.

`DecodedCommandLine` is **omitted** (not `null`) when no `-enc` flag is detected, so unencoded events keep their original 10-field shape. Decoding is **fail-soft**: malformed base64 or non-UTF-16-LE bytes produce no `DecodedCommandLine`, never an exception. Real Sysmon feeds are noisy and one bad event must not abort the run.

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

### Out of scope (deliberate)

- Event IDs other than 1.
- Splitting `Hashes` into a sub-object (currently emitted as the raw `"SHA1=...,MD5=..."` string).
- `-e` as a PowerShell encoded-command flag — prefix-ambiguous with `-ExecutionPolicy`, would cause false-positive decode attempts.
