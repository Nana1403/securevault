import tempfile
import unittest
from pathlib import Path

from securevault.database import VaultDatabase
from securevault.models import CredentialInput
from securevault.vault import (
    RecoveryLockedOutError,
    VaultLockedError,
    VaultService,
)

MASTER = "Emerald-River-Planet-Notebook-47!"


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test-vault.db"
        self.database = VaultDatabase(self.db_path)
        self.vault = VaultService(self.database)
        self.recovery = self.vault.setup(MASTER)

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def sample(self, **overrides):
        data = {
            "account_name": "Example",
            "website": "https://example.com",
            "username": "user@example.com",
            "password": "V3ry-Strong-Unique!Pass",
            "category": "Work",
            "tags": "demo, test",
            "notes": "Recovery email is configured.",
            "favorite": True,
        }
        data.update(overrides)
        return CredentialInput(**data)

    def test_master_password_unlock_and_recovery(self):
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.unlock("incorrect password")
        self.vault.unlock(MASTER)
        self.assertTrue(self.vault.unlocked)
        self.vault.lock()
        self.vault.unlock_with_recovery(self.recovery)
        self.assertTrue(self.vault.unlocked)

    def test_recovery_key_resets_forgotten_master_password(self):
        new_master = "Verdant-Orbit-Cascade-Falcon-82!"
        self.vault.save_credential(self.sample())
        self.vault.lock()

        self.vault.recover_master_password(self.recovery, new_master)
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(
            self.vault.list_credentials()[0].username, "user@example.com"
        )

        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.unlock(MASTER)
        self.vault.unlock(new_master)
        self.assertEqual(len(self.vault.list_credentials()), 1)

    def test_invalid_recovery_key_cannot_reset_password(self):
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.recover_master_password(
                "NOT-A-VALID-RECOVERY-KEY",
                "Verdant-Orbit-Cascade-Falcon-82!",
            )
        self.assertFalse(self.vault.unlocked)

    def test_recovery_locks_after_five_incorrect_keys(self):
        self.vault.lock()
        new_master = "Verdant-Orbit-Cascade-Falcon-82!"
        for attempt in range(1, 5):
            with self.assertRaisesRegex(
                VaultLockedError,
                f"{5 - attempt} recovery attempts remain",
            ):
                self.vault.recover_master_password(
                    f"INCORRECT-RECOVERY-KEY-{attempt}",
                    new_master,
                )

        with self.assertRaises(RecoveryLockedOutError):
            self.vault.recover_master_password(
                "INCORRECT-RECOVERY-KEY-5", new_master
            )
        with self.assertRaises(RecoveryLockedOutError):
            self.vault.recover_master_password(self.recovery, new_master)
        self.assertFalse(self.vault.unlocked)

    def test_weak_new_password_does_not_use_recovery_attempt(self):
        self.vault.lock()
        with self.assertRaises(ValueError):
            self.vault.recover_master_password(
                "INCORRECT-RECOVERY-KEY", "weak"
            )
        self.assertEqual(
            self.database.get_meta("recovery_failed_attempts"), "0"
        )

    def test_crud_is_encrypted_at_rest(self):
        credential_id = self.vault.save_credential(self.sample())
        raw = self.database.get_row(credential_id)
        self.assertNotIn("example.com", raw["website_enc"])
        self.assertNotIn("user@example.com", raw["username_enc"])
        self.assertNotIn("Strong", raw["password_enc"])
        restored = self.vault.get_credential(credential_id)
        self.assertEqual(restored.username, "user@example.com")
        self.assertEqual(restored.password, "V3ry-Strong-Unique!Pass")

        self.vault.save_credential(
            self.sample(account_name="Updated", password="Another-Good-Password!82"),
            credential_id,
        )
        self.assertEqual(self.vault.get_credential(credential_id).account_name, "Updated")
        self.vault.delete_credential(credential_id)
        self.assertEqual(self.vault.list_credentials(), [])

    def test_search_and_health_detect_reuse(self):
        self.vault.save_credential(self.sample())
        self.vault.save_credential(
            self.sample(
                account_name="School portal",
                username="student@school.edu",
                category="School",
            )
        )
        self.assertEqual(len(self.vault.list_credentials("school.edu")), 1)
        self.assertEqual(len(self.vault.list_credentials(category="Work")), 1)
        health = self.vault.health()
        self.assertEqual(health.total, 2)
        self.assertEqual(health.reused, 2)

    def test_encrypted_backup_restore(self):
        self.vault.save_credential(self.sample())
        backup = self.vault.backup()
        self.assertNotIn(b"user@example.com", backup)
        credential_id = self.vault.list_credentials()[0].id
        self.vault.delete_credential(credential_id)
        self.assertEqual(self.vault.restore(backup), 1)
        self.assertEqual(self.vault.list_credentials()[0].account_name, "Example")


if __name__ == "__main__":
    unittest.main()
