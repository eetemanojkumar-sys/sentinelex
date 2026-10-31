import unittest

from server.security import generate_secret, hash_password, hash_secret, verify_password


class SecurityPrimitiveTests(unittest.TestCase):
    def test_password_hash_round_trip(self):
        encoded = hash_password("Correct-Horse-Battery-2026!")
        self.assertTrue(verify_password("Correct-Horse-Battery-2026!", encoded))
        self.assertFalse(verify_password("wrong-password-value", encoded))

    def test_password_hash_uses_unique_salts(self):
        first = hash_password("Correct-Horse-Battery-2026!")
        second = hash_password("Correct-Horse-Battery-2026!")
        self.assertNotEqual(first, second)

    def test_password_length_is_enforced(self):
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_generated_secrets_are_unique_and_hashable(self):
        first = generate_secret()
        second = generate_secret()
        self.assertNotEqual(first, second)
        self.assertEqual(len(hash_secret(first)), 64)
        self.assertNotEqual(hash_secret(first), hash_secret(second))


if __name__ == "__main__":
    unittest.main()
