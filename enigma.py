from __future__ import annotations

import argparse
import getpass
import os
import sys

from base64 import urlsafe_b64encode, urlsafe_b64decode

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover
    print(
        "ERROR: the 'cryptography' package is required.\n"
        "Install it with:  pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)

MAGIC = b"ENIGMA1\x00"          # version tag so tokens are recognizable
SALT_LEN = 16                   # bytes of PBKDF2 salt (128 bits)
NONCE_LEN = 12                  # GCM standard nonce size
KEY_LEN = 32                    # AES-256
PBKDF2_ITERATIONS = 600_000     # OWASP minimum for interactive use

TOKEN_PREFIX = "enigma1."       # human-readable marker before the payload


# --------------------------------------------------------------------------- #
# Core primitives
# --------------------------------------------------------------------------- #
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the password and per-message salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(text: str, password: str) -> str:
    """Encrypt a UTF-8 message into a portable Enigma token."""
    if not text:
        raise ValueError("message is empty — nothing to encrypt")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)

    payload = AESGCM(key).encrypt(
        nonce, text.encode("utf-8"), associated_data=MAGIC
    )  # ciphertext + auth tag concatenated

    token_bytes = MAGIC + salt + nonce + payload
    body = urlsafe_b64encode(token_bytes).decode("ascii").rstrip("=")
    return TOKEN_PREFIX + body


def decrypt_message(token: str, password: str) -> str:
    """Decrypt an Enigma token. Raises ValueError on wrong password/format."""
    raw = normalize_token(token)

    if not raw.startswith(MAGIC):
        raise ValueError(
            "not a valid Enigma token (missing magic header). "
            "Did you copy the whole 'enigma1....' string?"
        )
    rest = raw[len(MAGIC):]
    if len(rest) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("token is truncated or corrupted")

    salt, nonce, payload = (
        rest[:SALT_LEN],
        rest[SALT_LEN : SALT_LEN + NONCE_LEN],
        rest[SALT_LEN + NONCE_LEN:],
    )
    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(
            nonce, payload, associated_data=MAGIC
        )
    except InvalidTag as exc:
        raise ValueError("decryption failed — wrong password or corrupted token") from exc

    return plaintext.decode("utf-8")


def normalize_token(token: str) -> bytes:
    """Accept tokens with/without the 'enigma1.' prefix, padding, whitespace."""
    t = token.strip()
    if t.startswith(TOKEN_PREFIX):
        t = t[len(TOKEN_PREFIX):]
    # restore stripped base64url padding
    return urlsafe_b64decode(t + "=" * (-len(t) % 4))


# --------------------------------------------------------------------------- #
# CLI helpers
# --------------------------------------------------------------------------- #
def get_password(prompt: str, confirm: bool = False) -> str:
    """Prompt without echoing; optionally require a second matching entry."""
    first = getpass.getpass(prompt)
    if not first:
        raise SystemExit("empty password is not allowed")
    if confirm:
        second = getpass.getpass("  (repeat the password to confirm)")
        if first != second:
            raise SystemExit("passwords do not match — aborted")
    return first


def read_source(args) -> str:
    """Input text: positional arg > -m flag > -f/stdin > interactive prompt."""
    if getattr(args, "text", None):
        return args.text
    if getattr(args, "message", None):
        return args.message
    path = getattr(args, "file", None)
    if path == "-":
        data = sys.stdin.read()
    elif path:
        with open(path, "r", encoding="utf-8") as fh:
            data = fh.read()
    else:
        # interactive mode for messages that don't fit on one command line
        print("Type the message (Ctrl-Z + Enter on Windows, Ctrl-D elsewhere to finish):")
        lines = []
        while True:
            try:
                lines.append(input())
            except EOFError:
                break
        data = "\n".join(lines)
    return data


def write_output(text: str, args, label: str) -> None:
    if getattr(args, "out", None):
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"OK — {label} written to {args.out}")
    else:
        print()
        print(text)


_STREAMS_RECONFIGURED = False


def _ensure_utf8_streams() -> None:
    """Windows consoles default to cp1252/legacy codepages; force UTF-8."""
    global _STREAMS_RECONFIGURED
    if _STREAMS_RECONFIGURED:
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # non-tty streams without reconfigure
            pass
    _STREAMS_RECONFIGURED = True


def main(argv=None) -> int:
    _ensure_utf8_streams()
    parser = argparse.ArgumentParser(
        prog="enigma.py",
        description="Encrypt and decrypt messages with AES-256-GCM (password-based).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "text",
        nargs="?",
        metavar="TEXT",
        help="the message (encrypt) or the enigma1. token (decrypt)",
    )
    common.add_argument("-m", "--message", help="alternative: pass the text via flag")
    common.add_argument("-f", "--file", help="read input from a file ('-' for stdin)")
    common.add_argument("--password", help="passphrase directly (otherwise you will be prompted)")
    common.add_argument("-o", "--out", help="write result to this file instead of stdout")

    enc = sub.add_parser("encrypt", parents=[common], help="message -> enigma token")
    dec = sub.add_parser(
        "decrypt",
        parents=[common],
        help="enigma token -> message (token can also come from -f/stdin)",
    )
    selftest = sub.add_parser("selftest", add_help=False, help="quick sanity check")

    args = parser.parse_args(argv)

    if args.command == "selftest":
        return run_selftest()

    try:
        text = read_source(args)
    except FileNotFoundError as exc:
        print(f"error: cannot open {exc.filename}", file=sys.stderr)
        return 1

    password = getattr(args, "password", None) or get_password(
        "Password: ", confirm=(args.command == "encrypt")
    )

    try:
        if args.command == "encrypt":
            result = encrypt_message(text, password)
            write_output(result, args, label="token")
        else:
            result = decrypt_message(text, password)
            write_output(result, args, label="decrypted message")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


def run_selftest() -> int:
    """Encrypt/decrypt round-trip with a fixed password, then verify failure modes."""
    sample = "The quick brown fox — ünïcode ✓ 42"
    pw = "selftest-password"

    token = encrypt_message(sample, pw)
    assert decrypt_message(token, pw) == sample, "round-trip mismatch"

    # different passwords must fail cleanly (authenticated encryption)
    try:
        decrypt_message(token, "wrong-password")
    except ValueError:
        pass
    else:
        print("FAIL: wrong password decrypted successfully?!")
        return 1

    # two tokens for the same message must differ (fresh salt/nonce)
    assert encrypt_message(sample, pw) != token

    print("selftest OK ✔  (round-trip, auth failure handling, uniqueness)")
    print(f"sample token: {token[:64]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
