# HashLookup — Engineering Report

## Overview

**Project:** HashLookup
**Version:** 1.0
**Author:** Sideways 8 Security Research
**Category:** Password Security / Hash Analysis

HashLookup identifies hash types by format and queries multiple online databases (CrackStation, Nitrx, Hashes.com) for reverse lookups. Designed for password recovery assessments, CTF challenges, and hash classification during security audits where you need quick hash identification without memorizing format patterns.

---

## Tech Stack

### Language: Python 3.10+

Stdlib-heavy for hash identification. The `hashlib` module handles local hash computation (though the tool queries online databases, not local brute-force).

### HTTP: `requests`

Used for online hash lookup API calls. Falls back gracefully if the module isn't installed — the hash identification mode works without it.

### Pattern matching: `re` (stdlib)

Hash type identification is regex-based. Each hash algorithm has a unique format signature (length, character set, prefix). The regex table maps ~15 common hash types from MD5 to bcrypt.

---

## Architecture Decisions

### Online lookup, not local cracking

Local brute-force is slow, CPU-intensive, and requires wordlists. Online databases have already cracked billions of hashes — querying them is seconds vs. hours. The tool queries 3 databases in parallel and aggregates results.

### Hash identification first, lookup second

Before querying anything, we identify the hash type(s). A hash can match multiple patterns (NTLM and MD5 both produce 32 hex characters). The tool flags ambiguities rather than guessing.

### Graceful dependency degradation

If `requests` isn't installed, the tool still works as a hash identifier. This matters on bare-metal pentest boxes where installing packages isn't always practical.

### No local rainbow tables

Rainbow table storage is significant (GB+ for comprehensive coverage). Online databases are the pragmatic choice for a CLI tool. If offline lookup is needed, the tool reports the hash type and the analyst can use `hashcat` with their own wordlists.

---

## File Structure

```
HashLookup/
├── hashlookup.py        # Hash ID and lookup
├── README.md            # Usage and examples
├── LICENSE              # MIT
├── requirements.txt     # requests
├── tests/
│   └── test_hashlookup.py
└── docs/
    └── engineering-report.md
```

---

## Limitations

1. **Online-only for cracked values** — no internet = no lookup results. Hash identification still works.
2. **Rate limited** — free-tier API endpoints have caps (typically 100-500 req/hr).
3. **No salt support** — salted hashes (Linux shadow, WordPress) cannot be looked up in public databases without knowing the salt.
4. **False positives on identification** — MD5 and NTLM are identical in format. The tool flags this but can't disambiguate without context.

---

## Future Work

- Add `hashcat` mode generation for offline cracking with local wordlists.
- Support for hashcat's 300+ module reference table.
- Add local wordlist lookup mode (`--wordlist /usr/share/wordlists/rockyou.txt`).
- Add hash-optimized lookup (detect NT hash by 32-char hex + context hints).
