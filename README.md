# SecretGlyph

Offline secret entropy prober and strong password generator.

Built by **Mourad.Soltani**

## What you get

A single-file Python CLI that:

- Analyzes Shannon entropy and strength of any string or password
- Scans directories for common secret patterns (AWS, GitHub, OpenAI-style keys, private keys, generic assignments) plus high-entropy candidates
- Generates cryptographically strong passwords (CSPRNG via `secrets`)
- Outputs human-readable or JSON
- Fully offline, stdlib only

## Quick start

```bash
python3 secretglyph.py health
python3 secretglyph.py analyze "myWeakPassword123"
python3 secretglyph.py generate --length 32
python3 secretglyph.py scan . --json
```

## Requirements

- Python 3.9+
- No external dependencies

## License

MIT — see LICENSE

Signature: Mourad.Soltani
