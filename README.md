# source-code-editor
``
A small Python script I built to scan code files for accidentally exposed API keys and credentials — things like AWS keys, GitHub tokens, Google API keys, etc. — using regular expressions.

## Why I built this

While learning about cybersecurity, I kept reading about developers accidentally pushing API keys and secrets to GitHub, which leads to real breaches. I wanted to build something practical that actually solves this problem instead of just another basic script. This is one of the projects I built for my portfolio while applying for scholarships.

## What it does

It scans a file (or an entire folder) line by line and checks each line against a set of regex patterns that match the known format of common API keys. If it finds something that looks like a real key, it flags it, tells you which line it's on, and masks most of the characters so the actual secret is never printed in full.

Right now it can catch:
- AWS Access Keys and Secret Keys
- Google API Keys
- Slack Tokens
- GitHub Tokens
- Generic Bearer Tokens
- Generic secrets/passwords/API keys written as key-value pairs
- Private key blocks (RSA, EC, DSA, PGP)

It also skips folders like `.git`, `node_modules`, and `venv` since there's no point scanning those.

## How to run it

To scan one file:
```bash
python main.py path/to/file.py
