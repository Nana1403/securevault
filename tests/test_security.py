import unittest

from securevault.security import (
    VaultDecryptionError,
    assess_password,
    decrypt_text,
    encrypt_text,
    generate_passphrase,
    generate_password,
)


class SecurityTests(unittest.TestCase):
    def test_authenticated_encryption_round_trip(self):
        key = bytes(range(32))
        token = encrypt_text("correct horse battery staple", key, "test")
        self.assertNotIn("correct", token)
        self.assertEqual(decrypt_text(token, key, "test"), "correct horse battery staple")
        with self.assertRaises(VaultDecryptionError):
            decrypt_text(token, bytes(reversed(range(32))), "test")

    def test_generator_honors_character_groups(self):
        generated = generate_password(
            40, uppercase=False, lowercase=False, numbers=True, symbols=False
        )
        self.assertEqual(len(generated), 40)
        self.assertTrue(generated.isdigit())

    def test_generator_rejects_empty_alphabet(self):
        with self.assertRaises(ValueError):
            generate_password(
                20, uppercase=False, lowercase=False, numbers=False, symbols=False
            )

    def test_passphrase_and_strength(self):
        phrase = generate_passphrase(4)
        self.assertEqual(len(phrase.split("-")), 5)
        self.assertEqual(assess_password("password123").label, "Weak")
        self.assertIn(assess_password(phrase).label, {"Good", "Strong"})


if __name__ == "__main__":
    unittest.main()
