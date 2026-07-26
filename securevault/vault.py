"""Vault setup, authentication, credential, health, and backup services."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from .database import VaultDatabase
from .models import Credential, CredentialInput, VaultHealth, utc_now
from .security import (
    assess_password,
    decrypt_text,
    derive_key,
    deserialize_encrypted_backup,
    encrypt_text,
    generate_recovery_key,
    password_verifier,
    serialize_encrypted_backup,
    unwrap_vault_key,
    verify_password,
    wrap_vault_key,
)

MAX_FAILED_ATTEMPTS = 5
MAX_RECOVERY_ATTEMPTS = 5
LOCKOUT_SECONDS = 30


class VaultLockedError(PermissionError):
    pass


class LoginLockedOutError(PermissionError):
    def __init__(self, seconds_remaining: int):
        self.seconds_remaining = seconds_remaining
        super().__init__(f"Try again in {seconds_remaining} seconds.")


class RecoveryLockedOutError(PermissionError):
    def __init__(self, seconds_remaining: int):
        self.seconds_remaining = seconds_remaining
        super().__init__(
            "Recovery is temporarily locked. "
            f"Try again in {seconds_remaining} seconds."
        )


class VaultService:
    def __init__(self, database: VaultDatabase):
        self.db = database
        self._vault_key: bytes | None = None

    @property
    def unlocked(self) -> bool:
        return self._vault_key is not None

    @staticmethod
    def _validate_master_password(password: str) -> None:
        if assess_password(password).score < 60 or len(password) < 12:
            raise ValueError(
                "The master password must be at least 12 characters and have "
                "Good or Strong strength."
            )

    def setup(self, master_password: str) -> str:
        if self.db.is_initialized():
            raise ValueError("This vault has already been set up.")
        self._validate_master_password(master_password)

        verifier_salt = secrets.token_bytes(16)
        wrapping_salt = secrets.token_bytes(16)
        recovery_salt = secrets.token_bytes(16)
        vault_key = secrets.token_bytes(32)
        recovery_key = generate_recovery_key()
        wrapping_key = derive_key(master_password, wrapping_salt)
        recovery_wrapping_key = derive_key(recovery_key, recovery_salt)

        self.db.set_meta_many(
            {
                "master_salt": base64.urlsafe_b64encode(verifier_salt).decode("ascii"),
                "master_verifier": password_verifier(master_password, verifier_salt),
                "wrapping_salt": base64.urlsafe_b64encode(wrapping_salt).decode("ascii"),
                "wrapped_vault_key": wrap_vault_key(
                    vault_key, wrapping_key, "master-key-wrap"
                ),
                "recovery_salt": base64.urlsafe_b64encode(recovery_salt).decode("ascii"),
                "recovery_verifier": password_verifier(recovery_key, recovery_salt),
                "recovery_wrapped_key": wrap_vault_key(
                    vault_key, recovery_wrapping_key, "recovery-key-wrap"
                ),
                "failed_attempts": "0",
                "lockout_until": "",
                "recovery_failed_attempts": "0",
                "recovery_lockout_until": "",
                "created_at": utc_now(),
                "inactivity_minutes": "5",
                "clipboard_seconds": "20",
                "old_password_days": "180",
            }
        )
        self._vault_key = vault_key
        return recovery_key

    def _lockout_remaining(self, meta_key: str = "lockout_until") -> int:
        value = self.db.get_meta(meta_key)
        if not value:
            return 0
        try:
            until = datetime.fromisoformat(value)
        except ValueError:
            return 0
        remaining = int((until - datetime.now(timezone.utc)).total_seconds())
        return max(0, remaining)

    def unlock(self, master_password: str) -> None:
        remaining = self._lockout_remaining()
        if remaining:
            raise LoginLockedOutError(remaining)
        salt_text = self.db.get_meta("master_salt")
        verifier = self.db.get_meta("master_verifier")
        if not salt_text or not verifier:
            raise ValueError("Vault has not been set up.")
        salt = base64.urlsafe_b64decode(salt_text)
        if not verify_password(master_password, salt, verifier):
            failures = int(self.db.get_meta("failed_attempts") or "0") + 1
            updates = {"failed_attempts": str(failures)}
            if failures >= MAX_FAILED_ATTEMPTS:
                until = datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_SECONDS)
                updates.update(
                    {"failed_attempts": "0", "lockout_until": until.isoformat()}
                )
            self.db.set_meta_many(updates)
            if failures >= MAX_FAILED_ATTEMPTS:
                raise LoginLockedOutError(LOCKOUT_SECONDS)
            raise VaultLockedError(
                f"Incorrect master password. {MAX_FAILED_ATTEMPTS - failures} attempts remain."
            )

        wrapping_salt = base64.urlsafe_b64decode(self.db.get_meta("wrapping_salt") or "")
        wrapping_key = derive_key(master_password, wrapping_salt)
        self._vault_key = unwrap_vault_key(
            self.db.get_meta("wrapped_vault_key") or "",
            wrapping_key,
            "master-key-wrap",
        )
        self.db.set_meta_many({"failed_attempts": "0", "lockout_until": ""})

    def unlock_with_recovery(self, recovery_key: str) -> None:
        self._vault_key = self._vault_key_from_recovery(recovery_key)

    def _vault_key_from_recovery(self, recovery_key: str) -> bytes:
        remaining = self._lockout_remaining("recovery_lockout_until")
        if remaining:
            raise RecoveryLockedOutError(remaining)

        salt_text = self.db.get_meta("recovery_salt") or ""
        verifier = self.db.get_meta("recovery_verifier") or ""
        salt = base64.urlsafe_b64decode(salt_text)
        normalized_recovery_key = recovery_key.strip().upper()
        if not verify_password(normalized_recovery_key, salt, verifier):
            failures = (
                int(self.db.get_meta("recovery_failed_attempts") or "0") + 1
            )
            updates = {"recovery_failed_attempts": str(failures)}
            if failures >= MAX_RECOVERY_ATTEMPTS:
                until = datetime.now(timezone.utc) + timedelta(
                    seconds=LOCKOUT_SECONDS
                )
                updates.update(
                    {
                        "recovery_failed_attempts": "0",
                        "recovery_lockout_until": until.isoformat(),
                    }
                )
            self.db.set_meta_many(updates)
            if failures >= MAX_RECOVERY_ATTEMPTS:
                raise RecoveryLockedOutError(LOCKOUT_SECONDS)
            raise VaultLockedError(
                "That recovery key is not valid. "
                f"{MAX_RECOVERY_ATTEMPTS - failures} recovery attempts remain."
            )

        wrapping_key = derive_key(normalized_recovery_key, salt)
        vault_key = unwrap_vault_key(
            self.db.get_meta("recovery_wrapped_key") or "",
            wrapping_key,
            "recovery-key-wrap",
        )
        self.db.set_meta_many(
            {
                "recovery_failed_attempts": "0",
                "recovery_lockout_until": "",
            }
        )
        return vault_key

    def change_master_password(self, new_password: str) -> None:
        key = self._require_key()
        self._validate_master_password(new_password)
        self._replace_master_password(key, new_password)

    def recover_master_password(
        self, recovery_key: str, new_master_password: str
    ) -> None:
        """Use the setup recovery key to replace a forgotten master password."""
        self._validate_master_password(new_master_password)
        vault_key = self._vault_key_from_recovery(recovery_key)
        self._replace_master_password(vault_key, new_master_password)
        self._vault_key = vault_key

    def _replace_master_password(
        self, vault_key: bytes, new_password: str
    ) -> None:
        verifier_salt = secrets.token_bytes(16)
        wrapping_salt = secrets.token_bytes(16)
        wrapping_key = derive_key(new_password, wrapping_salt)
        self.db.set_meta_many(
            {
                "master_salt": base64.urlsafe_b64encode(verifier_salt).decode("ascii"),
                "master_verifier": password_verifier(new_password, verifier_salt),
                "wrapping_salt": base64.urlsafe_b64encode(wrapping_salt).decode("ascii"),
                "wrapped_vault_key": wrap_vault_key(
                    vault_key, wrapping_key, "master-key-wrap"
                ),
                "failed_attempts": "0",
                "lockout_until": "",
                "recovery_failed_attempts": "0",
                "recovery_lockout_until": "",
            }
        )

    def lock(self) -> None:
        self._vault_key = None

    def _require_key(self) -> bytes:
        if self._vault_key is None:
            raise VaultLockedError("Unlock the vault first.")
        return self._vault_key

    def _decrypt_row(self, row: Any) -> Credential:
        key = self._require_key()
        return Credential(
            id=row["id"],
            account_name=row["account_name"],
            website=decrypt_text(row["website_enc"], key, "website"),
            username=decrypt_text(row["username_enc"], key, "username"),
            password=decrypt_text(row["password_enc"], key, "password"),
            category=row["category"],
            tags=row["tags"],
            notes=decrypt_text(row["notes_enc"], key, "notes"),
            favorite=bool(row["favorite"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_credentials(
        self, search: str = "", category: str = "All", favorites_only: bool = False
    ) -> list[Credential]:
        credentials = [self._decrypt_row(row) for row in self.db.all_rows()]
        needle = search.casefold().strip()
        if needle:
            credentials = [
                item
                for item in credentials
                if needle
                in " ".join(
                    (item.account_name, item.website, item.username, item.category, item.tags)
                ).casefold()
            ]
        if category != "All":
            credentials = [item for item in credentials if item.category == category]
        if favorites_only:
            credentials = [item for item in credentials if item.favorite]
        return credentials

    def get_credential(self, credential_id: int) -> Credential:
        row = self.db.get_row(credential_id)
        if row is None:
            raise KeyError("Credential not found.")
        return self._decrypt_row(row)

    def save_credential(
        self, data: CredentialInput, credential_id: int | None = None
    ) -> int:
        key = self._require_key()
        timestamp = utc_now()
        fields = {
            "account_name": data.account_name,
            "website_enc": encrypt_text(data.website, key, "website"),
            "username_enc": encrypt_text(data.username, key, "username"),
            "password_enc": encrypt_text(data.password, key, "password"),
            "category": data.category,
            "tags": data.tags,
            "notes_enc": encrypt_text(data.notes, key, "notes"),
            "favorite": int(data.favorite),
            "updated_at": timestamp,
        }
        if credential_id is None:
            fields["created_at"] = timestamp
            return self.db.insert_credential(fields)
        self.db.update_credential(credential_id, fields)
        return credential_id

    def delete_credential(self, credential_id: int) -> None:
        self._require_key()
        self.db.delete_credential(credential_id)

    def categories(self) -> list[str]:
        base = ["Social media", "School", "Work", "Banking", "Entertainment", "Other"]
        found = {item.category for item in self.list_credentials()}
        return base + sorted(found.difference(base), key=str.casefold)

    def health(self, old_days: int | None = None) -> VaultHealth:
        items = self.list_credentials()
        old_days = old_days or int(self.db.get_meta("old_password_days") or "180")
        cutoff = datetime.now(timezone.utc) - timedelta(days=old_days)
        fingerprints = Counter(
            hashlib.sha256(item.password.encode("utf-8")).digest() for item in items
        )
        weak = sum(assess_password(item.password).score < 60 for item in items)
        reused = sum(
            fingerprints[hashlib.sha256(item.password.encode("utf-8")).digest()] > 1
            for item in items
        )
        old = sum(datetime.fromisoformat(item.updated_at) < cutoff for item in items)
        incomplete = sum(not item.notes.strip() for item in items)
        total = len(items)
        if total == 0:
            score = 100
        else:
            penalty = (weak * 35 + reused * 30 + old * 20 + incomplete * 5) / total
            score = max(0, round(100 - penalty))
        return VaultHealth(
            total=total, weak=weak, reused=reused, old=old,
            incomplete=incomplete, score=score
        )

    def backup(self) -> bytes:
        key = self._require_key()
        payload = {
            "version": 1,
            "created_at": utc_now(),
            "credentials": self.db.export_rows(),
        }
        return serialize_encrypted_backup(payload, key)

    def restore(self, data: bytes) -> int:
        key = self._require_key()
        payload = deserialize_encrypted_backup(data, key)
        if payload.get("version") != 1 or not isinstance(payload.get("credentials"), list):
            raise ValueError("Unsupported or damaged backup.")
        # Authenticate every encrypted field before replacing current data.
        for row in payload["credentials"]:
            decrypt_text(row["website_enc"], key, "website")
            decrypt_text(row["username_enc"], key, "username")
            decrypt_text(row["password_enc"], key, "password")
            decrypt_text(row["notes_enc"], key, "notes")
        self.db.replace_rows(payload["credentials"])
        return len(payload["credentials"])
