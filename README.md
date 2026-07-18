# HashLookup

Hash identification and online lookup tool. Identifies hash types from format patterns and queries online databases (crackstation, hashes.com).

## Quick Start

```bash
# Identify a hash
python3 hashlookup.py -i d41d8cd98f00b204e9800998ecf8427e

# Compute hashes
python3 hashlookup.py -c "hello" -a md5

# Online lookup (needs requests)
python3 hashlookup.py -l -i 5d41402abc4b2a76b9719d911017c592

# Hashcat mode numbers
python3 hashlookup.py -i '$2b$12$LJ3m4ys3Lk' --hashcat-mode

# Read hash from file
python3 hashlookup.py -f hash.txt -i

# Save results
python3 hashlookup.py -i myhash -o results.json
```

## License

MIT
