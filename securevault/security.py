"""Cryptographic and password-quality helpers for SecureVault."""

from __future__ import annotations

import base64
import json
import secrets
import string
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

ARGON_ITERATIONS = 3
ARGON_LANES = 4
ARGON_MEMORY_KIB = 64 * 1024
KEY_LENGTH = 32

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
CONFUSING = set("O0oIl1|")
PASSPHRASE_WORDS = (
    "Amber", "Apple", "Atlas", "Birch", "Bloom", "Cedar", "Cloud", "Comet",
    "Coral", "Dawn", "Echo", "Ember", "Falcon", "Fern", "Forest", "Frost",
    "Galaxy", "Harbor", "Hazel", "Iris", "Jade", "Juniper", "Lagoon", "Lemon",
    "Maple", "Meadow", "Meteor", "Mint", "Nova", "Ocean", "Olive", "Orbit",
    "Pebble", "Pine", "Planet", "Quartz", "Raven", "River", "Sage", "Solar",
    "Sparrow", "Spruce", "Star", "Stone", "Summit", "Tiger", "Willow", "Zephyr",
)


class VaultDecryptionError(ValueError):
    """Raised when ciphertext cannot be authenticated and decrypted."""


def _argon(password: str, salt: bytes) -> bytes:
    return Argon2id(
        salt=salt,
        length=KEY_LENGTH,
        iterations=ARGON_ITERATIONS,
        lanes=ARGON_LANES,
        memory_cost=ARGON_MEMORY_KIB,
    ).derive(password.encode("utf-8"))


def derive_key(secret: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password or recovery key using Argon2id."""
    return _argon(secret, salt)


def password_verifier(password: str, salt: bytes) -> str:
    """Create a base64 verifier. The password itself is never retained."""
    return base64.urlsafe_b64encode(_argon(password, salt)).decode("ascii")


def verify_password(password: str, salt: bytes, verifier: str) -> bool:
    try:
        candidate = base64.urlsafe_b64decode(verifier.encode("ascii"))
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(_argon(password, salt), candidate)


def encrypt_text(value: str, key: bytes, purpose: str = "credential") -> str:
    nonce = secrets.token_bytes(12)
    aad = purpose.encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), aad)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_text(token: str, key: bytes, purpose: str = "credential") -> str:
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        return AESGCM(key).decrypt(
            raw[:12], raw[12:], purpose.encode("utf-8")
        ).decode("utf-8")
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise VaultDecryptionError("Encrypted data could not be authenticated.") from exc


def wrap_vault_key(vault_key: bytes, wrapping_key: bytes, purpose: str) -> str:
    return encrypt_text(
        base64.urlsafe_b64encode(vault_key).decode("ascii"), wrapping_key, purpose
    )


def unwrap_vault_key(token: str, wrapping_key: bytes, purpose: str) -> bytes:
    encoded = decrypt_text(token, wrapping_key, purpose)
    return base64.urlsafe_b64decode(encoded.encode("ascii"))


def generate_recovery_key() -> str:
    """Return a high-entropy, human-transcribable recovery key."""
    groups = [secrets.token_hex(3).upper() for _ in range(6)]
    return "-".join(groups)


def generate_password(
    length: int = 20,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    exclude_confusing: bool = True,
) -> str:
    length = max(8, min(128, int(length)))
    pools: list[str] = []
    for enabled, chars in (
        (uppercase, string.ascii_uppercase),
        (lowercase, string.ascii_lowercase),
        (numbers, string.digits),
        (symbols, SYMBOLS),
    ):
        if enabled:
            if exclude_confusing:
                chars = "".join(ch for ch in chars if ch not in CONFUSING)
            pools.append(chars)
    if not pools:
        raise ValueError("Select at least one character group.")
    if length < len(pools):
        raise ValueError("Length is too short for the selected options.")

    result = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    result.extend(secrets.choice(alphabet) for _ in range(length - len(result)))
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def generate_passphrase(word_count: int = 4, separator: str = "-") -> str:
    count = max(3, min(8, int(word_count)))
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(count)]
    words.append(str(secrets.randbelow(90) + 10))
    return separator.join(words)


@dataclass(frozen=True)
class PasswordAssessment:
    score: int
    label: str
    suggestions: tuple[str, ...]


def assess_password(password: str) -> PasswordAssessment:
    """A transparent local heuristic; it never sends passwords elsewhere."""
    suggestions: list[str] = []
    if not password:
        return PasswordAssessment(0, "Weak", ("Add a password.",))

    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password),
        )
    )
    score = min(45, len(password) * 3) + classes * 11
    lowered = password.lower()
    if any(word in lowered for word in ("password", "qwerty", "letmein", "admin", "1234")):
        score -= 30
        suggestions.append("Avoid common words and sequences.")
    if len(set(password)) < max(4, len(password) // 3):
        score -= 15
        suggestions.append("Use a wider variety of characters.")
    if len(password) < 12:
        suggestions.append("Use at least 12 characters.")
    if classes < 3 and len(password) < 20:
        suggestions.append("Mix character types or use a longer passphrase.")

    score = max(0, min(100, score))
    if score < 40:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Good"
    else:
        label = "Strong"
    return PasswordAssessment(score, label, tuple(suggestions))


def serialize_encrypted_backup(payload: dict, key: bytes) -> bytes:
    token = encrypt_text(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
        key,
        "securevault-backup-v1",
    )
    return ("SECUREVAULT-BACKUP-V1\n" + token).encode("utf-8")


def deserialize_encrypted_backup(data: bytes, key: bytes) -> dict:
    text = data.decode("utf-8")
    header, separator, token = text.partition("\n")
    if separator != "\n" or header != "SECUREVAULT-BACKUP-V1":
        raise ValueError("This is not a SecureVault backup.")
    return json.loads(decrypt_text(token, key, "securevault-backup-v1"))
