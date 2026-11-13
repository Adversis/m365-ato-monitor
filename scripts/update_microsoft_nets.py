"""Make function/microsoft_nets.json: the IP ranges that only Microsoft 365's own servers use.

The session and mail access checks skip records (not sign-ins) from these
ranges: the IP is a Microsoft server, not the client. The ranges are:

    each range of the Office 365 endpoints list
    minus each range of each Azure service tag (ServiceTags_Public).

The Azure service tags include all Azure address space that a customer can
use. The script also checks that no prefix of INTERNAL_NETS
(function/microsoft_nets.py, kept by hand) is in an Azure service tag.

    python3 scripts/update_microsoft_nets.py           # write the file
    python3 scripts/update_microsoft_nets.py --check   # compare only (CI, every month)

Exit code 0: the file is current (--check) or written. 1: the file is not
current (--check), or an INTERNAL_NETS prefix is in an Azure service tag.
2: a list could not be downloaded or read. After a write, run the tests,
commit the file, and deploy (./install.ps1 -Update).
"""

import ipaddress
import json
import re
import sys
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "function"))
import microsoft_nets  # noqa: E402

OUT = microsoft_nets.DATA_FILE
SERVICE_TAGS_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
SERVICE_TAGS_RE = re.compile(r"https://download\.microsoft\.com/download/[^\"']+/ServiceTags_Public_\d+\.json")
ENDPOINTS_URL = "https://endpoints.office.com/endpoints/worldwide?NoURLs&clientrequestid={}"


def _intervals(prefixes, version: int) -> list:
    """Merged, sorted (first, last) address pairs of the prefixes of one IP version."""
    nets = ipaddress.collapse_addresses(n for n in (ipaddress.ip_network(p, strict=False) for p in prefixes)
                                        if n.version == version)
    return sorted((int(n.network_address), int(n.broadcast_address)) for n in nets)


def _subtract(keep: list, remove: list) -> list:
    """The addresses in ``keep`` that are not in ``remove`` (both merged and sorted)."""
    out, j = [], 0
    for start, end in keep:
        while j < len(remove) and remove[j][1] < start:
            j += 1
        k, cur = j, start
        while k < len(remove) and remove[k][0] <= end:
            if remove[k][0] > cur:
                out.append((cur, remove[k][0] - 1))
            cur = max(cur, remove[k][1] + 1)
            k += 1
        if cur <= end:
            out.append((cur, end))
    return out


def safe_prefixes(endpoint_prefixes, tag_prefixes) -> list:
    """The Office 365 endpoint ranges minus the Azure service tag ranges, as sorted CIDR strings."""
    out = []
    for version, cls in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        for start, end in _subtract(_intervals(endpoint_prefixes, version), _intervals(tag_prefixes, version)):
            out.extend(str(n) for n in ipaddress.summarize_address_range(cls(start), cls(end)))
    return out


def tag_overlaps(nets, tags: dict) -> list:
    """(prefix, tag name, tag prefix) for each prefix of ``nets`` in a service tag. tags: {name: [prefix]}."""
    out = []
    mine = [ipaddress.ip_network(n) for n in nets]
    for name, prefixes in tags.items():
        for text in prefixes:
            other = ipaddress.ip_network(text, strict=False)
            out.extend((str(n), name, str(other)) for n in mine if n.version == other.version and n.overlaps(other))
    return out


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "m365-ato-monitor-ci"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read()


def published_lists() -> tuple:
    """({tag name: [prefix]}, [Office 365 endpoint prefix], the service tags file name)."""
    page = _get(SERVICE_TAGS_PAGE).decode("utf-8", "replace")
    match = SERVICE_TAGS_RE.search(page)
    if not match:
        raise ValueError("no ServiceTags_Public link on the download page")
    tags = json.loads(_get(match.group(0)))
    tag_lists = {v["name"]: v["properties"]["addressPrefixes"] for v in tags["values"]}
    endpoints = json.loads(_get(ENDPOINTS_URL.format(uuid.uuid4())))
    endpoint_prefixes = [ip for e in endpoints for ip in e.get("ips", [])]
    if len(tag_lists) < 100 or len(endpoint_prefixes) < 20:
        raise ValueError(f"the lists look incomplete ({len(tag_lists)} tags, {len(endpoint_prefixes)} prefixes)")
    name = match.group(0).rsplit("/", 1)[-1]
    print(f"Read {name} ({len(tag_lists)} tags) and {len(endpoints)} Office 365 endpoint sets.")
    return tag_lists, endpoint_prefixes, name


def main(argv: list) -> int:
    check = "--check" in argv
    try:
        tags, endpoints, tags_name = published_lists()
    except Exception as e:
        print(f"ERROR: could not read Microsoft's IP lists: {type(e).__name__}: {e}")
        return 2
    code = 0
    for net, name, other in tag_overlaps(microsoft_nets.INTERNAL_NETS, tags):
        print(f"OVERLAP: INTERNAL_NETS prefix {net} overlaps {other} in the Azure service tag {name}. "
              "Remove it from function/microsoft_nets.py.")
        code = 1
    new = safe_prefixes(endpoints, [p for prefixes in tags.values() for p in prefixes])
    old = microsoft_nets.load_prefixes(OUT) if OUT.exists() else []
    added, removed = sorted(set(new) - set(old)), sorted(set(old) - set(new))
    print(f"{len(new)} prefixes; {len(added)} added and {len(removed)} removed since the file.")
    for label, items in (("removed", removed), ("added", added)):
        for p in items[:20]:
            print(f"  {label}: {p}")
        if len(items) > 20:
            print(f"  ... {len(items) - 20} more {label}")
    if check:
        if added or removed:
            print("The file is not current. Run python3 scripts/update_microsoft_nets.py, commit "
                  "function/microsoft_nets.json, and deploy. Removed prefixes matter most: the monitor "
                  "skips records from them until the update.")
            return 1
        return code
    if code:
        return code
    OUT.write_text(json.dumps({
        "about": "Generated by scripts/update_microsoft_nets.py. Office 365 endpoint ranges minus all Azure "
                 "service tag ranges. Do not edit.",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "service_tags": tags_name,
        "prefixes": new,
    }, indent=1) + "\n", encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
