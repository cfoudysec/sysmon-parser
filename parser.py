#!/usr/bin/env python3
import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

EVENT_DATA_FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

INTEGRITY_LEVELS = ["High", "Medium", "Low", "System"]

ENC_FLAGS = {"-enc", "-encodedcommand", "-ec"}


def decode_powershell_enc(commandline):
    tokens = commandline.split()
    for i, tok in enumerate(tokens):
        if tok.lower() in ENC_FLAGS and i + 1 < len(tokens):
            try:
                raw = base64.b64decode(tokens[i + 1], validate=False)
                return raw.decode("utf-16-le")
            except (ValueError, UnicodeDecodeError):
                return None
    return None


def parse_event(event):
    system = event.find("e:System", NS)
    data = event.find("e:EventData", NS)

    result = {
        "EventID": (system.findtext("e:EventID", default="", namespaces=NS) or "").strip(),
        "Computer": (system.findtext("e:Computer", default="", namespaces=NS) or "").strip(),
    }

    by_name = {d.get("Name"): (d.text or "") for d in data.findall("e:Data", NS)}
    for field in EVENT_DATA_FIELDS:
        result[field] = by_name.get(field, "")

    try:
        result["EventID"] = int(result["EventID"])
    except ValueError:
        pass

    ordered = ["EventID", "UtcTime", "Image", "CommandLine", "User",
               "IntegrityLevel", "ParentImage", "ParentCommandLine",
               "Computer", "Hashes"]
    out = {k: result[k] for k in ordered}

    decoded = decode_powershell_enc(out["CommandLine"])
    if decoded is not None:
        new_out = {}
        for k, v in out.items():
            new_out[k] = v
            if k == "CommandLine":
                new_out["DecodedCommandLine"] = decoded
        out = new_out
    return out


def matches(event, image, user, integrity, cmdline):
    if image is not None and image.lower() not in event["Image"].lower():
        return False
    if user is not None and event["User"] != user:
        return False
    if integrity is not None and event["IntegrityLevel"] != integrity:
        return False
    if cmdline:
        cl = event["CommandLine"].lower()
        decoded = event.get("DecodedCommandLine", "").lower()
        if not any(n.lower() in cl or (decoded and n.lower() in decoded) for n in cmdline):
            return False
    return True


def main(argv):
    p = argparse.ArgumentParser(description="Parse Sysmon Event ID 1 XML to JSON.")
    p.add_argument("path", help="Path to a Sysmon XML file")
    p.add_argument("--image", help="Keep events whose Image contains this substring (case-insensitive)")
    p.add_argument("--user", help="Keep events whose User exactly matches this value")
    p.add_argument("--integrity", choices=INTEGRITY_LEVELS,
                   help="Keep events with this IntegrityLevel")
    p.add_argument("--cmdline", action="append", metavar="SUBSTRING",
                   help="Keep events whose CommandLine contains this substring "
                        "(case-insensitive). Repeat to OR multiple substrings. "
                        "For values starting with '-', use --cmdline=-enc.")
    args = p.parse_args(argv[1:])

    tree = ET.parse(args.path)
    root = tree.getroot()

    if root.tag == f"{{{NS['e']}}}Event":
        events = [root]
    else:
        events = root.findall("e:Event", NS)

    parsed = [parse_event(e) for e in events]

    filtering = any(v for v in (args.image, args.user, args.integrity, args.cmdline))
    if filtering:
        parsed = [e for e in parsed
                  if matches(e, args.image, args.user, args.integrity, args.cmdline)]
        output = parsed
    else:
        output = parsed[0] if len(parsed) == 1 else parsed

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
