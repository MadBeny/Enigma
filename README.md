# Enigma 🔒

A reliable command-line tool for **encrypting and decrypting messages** from your terminal. Give it plain text, get back an opaque `enigma1....` token; give it the token plus the same password, and your original message comes back.

> ⚠️ WARNING: This has nothing to do with the WWII Enigma machine — under the hood it uses modern, well-vetted cryptography (AES-256-GCM).

---

## How it works

| Piece | What it does |
| --- | --- |
| **AES-256-GCM** | Authenticated encryption. You can't decrypt a corrupted or tampered token — you get an error instead of garbage output. |
| **PBKDF2-HMAC-SHA256** (600,000 iterations) | Derives your 256-bit key from the password. The iteration count is the OWASP minimum for interactive use, making brute-force attacks on weak passwords expensive. |
| **Random salt + nonce per message** | A fresh 16-byte salt and 12-byte nonce are generated for *every* encryption, so encrypting the same text twice with the same password produces two completely different tokens. |

### Token format

Everything is packed into one self-contained string:

```
enigma1.<base64url( magic header ‖ salt (16 B) ‖ nonce (12 B) ‖ ciphertext + auth tag )>
```

- No keys are stored in the token — only someone who knows the password can read it.
- The token is portable: paste it into a chat, email, file, or note and decrypt it later on any machine with Python + `cryptography` installed.

---

## Requirements

- **Python 3.8+**
- The [`cryptography`](https://pypi.org/project/cryptography/) package

```bash
pip install cryptography
```

That's the only dependency.

---

## Usage

### Encrypt a message

```bash
# Interactive (recommended): password is typed twice, never shown on screen
python enigma.py encrypt "hello secret world"

# Or pass the password directly (note: visible in shell history!)
python enigma.py encrypt --password behnam61 "top secret"

# Long text? Feed it from a file — output token goes to stdout or -o FILE
python enigma.py encrypt -f note.txt -o secret.token
```

### Decrypt a message

```bash
# Interactive: paste the full "enigma1...." token when prompted, then type the password
python enigma.py decrypt "enigma1.RU5JR01B..."

# From a file into another file
python enigma.py decrypt -f secret.token -o recovered.txt --password behnam61
```

### Other options (both commands)

| Flag | Meaning |
| --- | --- |
| `TEXT` | Positional: the message (encrypt) or the token (decrypt). Omit it to type/paste interactively. |
| `-m, --message` | Pass the text via flag instead of positionally. |
| `-f, --file` | Read input from a file (`-` means stdin). |
| `--password` | Supply the passphrase directly (otherwise you're prompted — safer for terminal history). |
| `-o, --out` | Write the result to a file instead of stdout. |

### Self-test

```bash
python enigma.py selftest
# → selftest OK ✔  (round-trip, auth failure handling, uniqueness)
```

Runs an encrypt/decrypt round trip with Unicode text, verifies that wrong passwords are rejected cleanly, and confirms tokens are unique per message.

---

## Security notes & best practices

- **Your password is everything.** The token contains no key — but a weak password can be brute-forced even against PBKDF2. Use a long passphrase (a random 4–6 words or more), not a dictionary word.
- **Wrong password = hard failure, never garbage.** GCM authentication means decryption either succeeds with the exact original text or raises an error. There is no "almost decoded" state to misread as real.
- **Prefer interactive mode** (`python enigma.py encrypt "text"` without `--password`) so your passphrase doesn't land in shell history, process lists, or CI logs.
- If you ever lose the password, the message is unrecoverable by design — that's the point of it.
