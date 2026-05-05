# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Python tool that parses Sysmon (Microsoft System Monitor) XML event logs and extracts fields from **Event ID 1 (Process Creation)** events into JSON.

The repository is currently empty — code has not been written yet.

## Fields to extract from Event ID 1

- `EventID`
- `UtcTime`
- `Image` (process path)
- `CommandLine`
- `User`
- `IntegrityLevel`
- `ParentImage`
- `ParentCommandLine`
- `Computer`
- `Hashes`
- `DecodedCommandLine` (derived; present only when CommandLine contains a PowerShell `-enc`/`-EncodedCommand`/`-ec` flag whose payload decodes successfully as base64 + UTF-16-LE)

## Output format

JSON. A single event produces one JSON object; multiple events produce a JSON array of objects.

## To be filled in once code exists

- Entry point / CLI invocation
- Build, lint, and test commands (including how to run a single test)
- Module layout and how parsing/output stages are separated
