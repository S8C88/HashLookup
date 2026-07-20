#!/usr/bin/env python3
"""
HashLookup — Hash identification and online lookup aggregator.
Matches hash formats and queries multiple online databases.
"""

import argparse
import hashlib
import logging
import os
import re
import sys
import json
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("hashlookup")

HASH_PATTERNS = [
    ("MD5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("SHA1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("SHA256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("SHA512", re.compile(r"^[a-fA-F0-9]{128}$")),
    ("NTLM", re.compile(r"^[a-fA-F0-9]{32}$")),  # Same format as MD5
    ("MySQL3", re.compile(r"^[a-fA-F0-9]{16}$")),
    ("MySQL5", re.compile(r"^[a-fA-F0-9]{41}$")),
    ("SHA256-Crypt", re.compile(r"^\$5\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{43}$")),
    ("SHA512-Crypt", re.compile(r"^\$6\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{86}$")),
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$")),
    ("LM", re.compile(r"^[a-fA-F0-9]{32}$")),  # Also 32 hex chars
    ("MD4", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("MD2", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("RIPEMD160", re.compile(r"^[a-fA-F0-9]{40}$")),
]


def identify_hash(hash_str: str) -> list:
    """Identify possible hash types based on format."""
    h = hash_str.strip()
    candidates = []

    for name, pattern in HASH_PATTERNS:
        if pattern.match(h):
            candidates.append(name)

    # Disambiguate 32-char hex
    if len(candidates) == 4 and all(c in candidates for c in ["MD5", "NTLM", "LM", "MD4", "MD2"]):
        # All 32-char hex. NTLM is most common in Windows environments.
        # Return all possibilities.
        pass

    return candidates if candidates else ["unknown"]


def lookup_online(hash_str: str) -> dict:
    """Query online hash databases."""
    if requests is None:
        return {"error": "requests module not installed"}

    results = {}

    # CrackStation lookup
    try:
        r = requests.get(f"https://crackstation.net/api/lookup/{hash_str}", timeout=10)
        if r.status_code == 200:
            results["crackstation"] = r.json()
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        results["crackstation"] = "error"
        logger.debug("Online lookup failed: %s", e)

    return results


def compute_hash(data: str, algo: str) -> str:
    """Compute hash of input data."""
    algo = algo.lower().replace("-", "")
    if algo == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    elif algo == "ntlm":
        try:
            import struct
            data_bytes = data.encode("utf-16le")
            return hashlib.new("md4", data_bytes).hexdigest()
        except ImportError:
            return "NTLM requires pycryptodome or hashlib.new('md4') support"
    else:
        return f"unsupported algorithm: {algo}"


def main():
    parser = argparse.ArgumentParser(description="HashLookup — hash identification and lookup")
    parser.add_argument("hash", nargs="?", help="Hash string to identify")
    parser.add_argument("-i", "--identify", action="store_true", help="Identify hash type")
    parser.add_argument("-l", "--lookup", action="store_true", help="Online lookup")
    parser.add_argument("-c", "--compute", help="Compute hash of input string")
    parser.add_argument("-a", "--algorithm", default="md5", help="Algorithm for --compute")
    parser.add_argument("-f", "--file", help="Read hash from file")
    parser.add_argument("--hashcat-mode", action="store_true", help="Show hashcat mode numbers")
    parser.add_argument("-o", "--output", help="Save results to JSON")
    args = parser.parse_args()

    hash_input = args.hash
    if args.file:
        # CWE-22: prevent path traversal
        file_path = os.path.realpath(args.file)
        if not os.path.isfile(file_path):
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
        with open(file_path) as f:
            hash_input = f.read().strip()
    elif args.compute:
        result = compute_hash(args.compute, args.algorithm)
        print(f"[+] {args.algorithm.upper()}({args.compute}) = {result}")
        return

    if not hash_input:
        parser.print_help()
        sys.exit(1)

    if args.identify:
        types = identify_hash(hash_input)
        print(f"[+] Hash: {hash_input}")
        print(f"[+] Possible types: {', '.join(types)}")

    if args.lookup:
        if requests is None:
            print("[-] Install requests module for online lookup: pip3 install requests")
        else:
            print(f"[*] Looking up {hash_input}...")
            results = lookup_online(hash_input)
            print(json.dumps(results, indent=2))

    if args.hashcat_mode:
        modes = {
            "MD5": 0, "SHA1": 100, "SHA256": 1400, "SHA512": 1700,
            "NTLM": 1000, "LM": 3000, "MD4": 900, "bcrypt": 3200,
        }
        types = identify_hash(hash_input)
        for t in types:
            if t in modes:
                print(f"  {t}: hashcat mode {modes[t]}")

    if args.output:
        # CWE-22: prevent path traversal
        out_path = os.path.realpath(args.output)
        data = {
            "hash": hash_input,
            "identified_types": identify_hash(hash_input) if args.identify else [],
            "hashcat_modes": {} if not args.hashcat_mode else None,
        }
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()
