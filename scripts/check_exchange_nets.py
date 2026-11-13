"""Check EXCHANGE_SERVER_NETS (function/mail_access.py) against Microsoft's published IP lists.

The monitor ignores Exchange records from these prefixes: it treats them as
Exchange Online's own servers. That is safe only while no customer can get
an IP in them. This script fails if a prefix overlaps:

- an Azure service tag (ServiceTags_Public: all Azure public address space,
  including customer VMs), or
- the Office 365 endpoints list (client-facing Microsoft 365 addresses; an
  overlap means the prefix is not internal server space).

CI runs it every month (.github/workflows/exchange-nets.yml). Run it by hand
before you add a prefix:

    python3 scripts/check_exchange_nets.py

Exit code 0: no overlap. 1: an overlap (the output names it). 2: a list
could not be downloaded or read.
"""

import ast
import ipaddress
import json
import re
import sys
import urllib.request
import uuid
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "function" / "mail_access.py"
SERVICE_TAGS_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
SERVICE_TAGS_RE = re.compile(r"https://download\.microsoft\.com/download/[^\"']+/ServiceTags_Public_\d+\.json")
ENDPOINTS_URL = "https://endpoints.office.com/endpoints/worldwide?NoURLs&clientrequestid={}"


def configured_nets(source: str) -> list:
    """The prefixes in the EXCHANGE_SERVER_NETS assignment of ``source`` (Python code)."""
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "EXCHANGE_SERVER_NETS"
                                                 for t in node.targets)):
            return [ipaddress.ip_network(c.value) for c in ast.walk(node.value)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)]
    raise ValueError("EXCHANGE_SERVER_NETS not found")


def overlaps(nets: list, published: dict) -> list:
    """(our prefix, list name, published prefix) for each overlap. ``published``: {name: [prefix, ...]}."""
    out = []
    for name, prefixes in published.items():
        for text in prefixes:
            other = ipaddress.ip_network(text, strict=False)
            for net in nets:
                if net.version == other.version and net.overlaps(other):
                    out.append((str(net), name, str(other)))
    return out


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "m365-ato-monitor-ci"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read()


def published_lists() -> dict:
    page = _get(SERVICE_TAGS_PAGE).decode("utf-8", "replace")
    match = SERVICE_TAGS_RE.search(page)
    if not match:
        raise ValueError("no ServiceTags_Public link on the download page")
    tags = json.loads(_get(match.group(0)))
    lists = {f"Azure service tag {v['name']}": v["properties"]["addressPrefixes"] for v in tags["values"]}
    endpoints = json.loads(_get(ENDPOINTS_URL.format(uuid.uuid4())))
    lists["Office 365 endpoints"] = [ip for e in endpoints for ip in e.get("ips", [])]
    print(f"Read {match.group(0).rsplit('/', 1)[-1]} ({len(tags['values'])} tags) and "
          f"{len(endpoints)} Office 365 endpoint sets.")
    return lists


def main() -> int:
    nets = configured_nets(SOURCE.read_text(encoding="utf-8"))
    try:
        lists = published_lists()
    except Exception as e:
        print(f"ERROR: could not read Microsoft's IP lists: {type(e).__name__}: {e}")
        return 2
    found = overlaps(nets, lists)
    for net, name, other in found:
        print(f"OVERLAP: {net} overlaps {other} in {name}")
    if found:
        print("Remove the prefix from EXCHANGE_SERVER_NETS, or confirm that the overlap is safe.")
        return 1
    print(f"OK: {', '.join(map(str, nets))} is in no published Microsoft list.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
