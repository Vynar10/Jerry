Jerry is a small simple password/encryption program made in python, process of learning cryptography, I/O and a step process of relearning python basics.


Current Features:
- Generate random passwords within your range of preferred digits for the length ->
        - ranges: 20, 40, etc.
        - choices of ascii or byte characters.

- Derive keys with Argon2id.
- Store encrypted '.jer' entries -> '.jer' being a literal reskin of json lmao.
- You can also derive from '.jer' files.

## Requirements

- Python 3
- PyNaCl
- argon2-cffi

Install dependencies:

```bash
python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

python main.py
```

If you use fish console use this instead:

```bash
source .venv/bin/activate.fish
```
