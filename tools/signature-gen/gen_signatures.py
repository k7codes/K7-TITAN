#!/usr/bin/env python3
"""K7 TITAN signature generator.

Walks the sample directory, computes multiple hashes per file and writes a
signature database. Also seeds well-known test signatures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# Well-known signatures that should always be present in the database.
KNOWN = [
    {
        "name": "EICAR-Test-File",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "severity": "test",
    },
]


@dataclass
class Signature:
    name: str
    sha256: str
    sha1: str = ""
    md5: str = ""
    size: int = 0
    entropy: float = 0.0
    severity: str = "unknown"


def hashes(path: Path) -> tuple[str, str, str, int, float]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    size = 0
    counts = [0] * 256

    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            size += len(chunk)
            for b in chunk:
                counts[b] += 1

    entropy = 0.0
    if size:
        for c in counts:
            if c:
                p = c / size
                entropy -= p * math.log2(p)

    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size, round(entropy, 4)


def build(sample_dir: Path) -> dict:
    signatures: list[dict] = []
    seen: set[str] = set()

    for sig in KNOWN:
        signatures.append(sig)
        seen.add(sig["sha256"])

    if sample_dir.is_dir():
        for root, _dirs, files in os.walk(sample_dir):
            for fn in files:
                path = Path(root) / fn
                try:
                    sha256, sha1, md5, size, entropy = hashes(path)
                except OSError:
                    continue
                if sha256 in seen:
                    continue
                seen.add(sha256)
                signatures.append(
                    asdict(Signature(
                        name=fn,
                        sha256=sha256,
                        sha1=sha1,
                        md5=md5,
                        size=size,
                        entropy=entropy,
                        severity="sample",
                    ))
                )

    return {
        "version": "0.2.0",
        "generator": "k7titan-signature-gen",
        "count": len(signatures),
        "signatures": signatures,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="K7 TITAN signature generator")
    parser.add_argument("--sample-dir", default="data/sample", help="directory to hash")
    parser.add_argument("--out", default="data/signatures/db.json", help="output database")
    parser.add_argument("--check", help="look up a sha256 in an existing database")
    args = parser.parse_args(argv)

    if args.check:
        with open(args.out, encoding="utf-8") as fh:
            db = json.load(fh)
        needle = args.check.lower()
        hit = next((s for s in db.get("signatures", []) if s.get("sha256") == needle), None)
        print(json.dumps(hit, indent=2) if hit else f"not found: {needle}")
        return 0 if hit else 1

    db = build(Path(args.sample_dir))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(db, indent=2), encoding="utf-8")
    print(f"wrote {db['count']} signature(s) to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
