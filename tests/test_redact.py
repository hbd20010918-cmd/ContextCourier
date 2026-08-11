from __future__ import annotations

import unittest

from contextcourier.redact import MARKER_PREFIX, redact_text


class RedactionTests(unittest.TestCase):
    def test_known_tokens_are_removed_without_storing_original(self) -> None:
        openai_key = "sk-proj-" + ("A" * 32)
        github_key = "ghp_" + ("b" * 36)
        source = f"first={openai_key}\nsecond={github_key}\n"

        result = redact_text(source)

        self.assertNotIn(openai_key, result.text)
        self.assertNotIn(github_key, result.text)
        self.assertEqual(result.counts["OPENAI_API_KEY"], 1)
        self.assertEqual(result.counts["GITHUB_TOKEN"], 1)
        self.assertIn(MARKER_PREFIX, result.text)

    def test_generic_assignments_keep_the_key_and_quotes(self) -> None:
        value = "correct-horse-battery-staple"
        key = "pass" + "word"
        result = redact_text(f'{key} = "{value}"\n')

        self.assertNotIn(value, result.text)
        self.assertIn(f'{key} = "<<CONTEXTCOURIER_REDACTED:GENERIC_SECRET>>"', result.text)
        self.assertEqual(result.total, 1)

    def test_placeholders_are_not_reported_as_secrets(self) -> None:
        source = "API_KEY=${OPENAI_API_KEY}\npassword=CHANGE_ME\ntoken=your_token_here\n"
        result = redact_text(source)

        self.assertEqual(result.text, source)
        self.assertEqual(result.total, 0)

    def test_secret_key_variants_and_real_example_substrings_are_redacted(self) -> None:
        first_key = "SECRET" + "_KEY"
        second_key = "aws_" + "secret_" + "access_" + "key"
        third_key = "pass" + "word"
        source = "\n".join(
            (
                f"{first_key}=alpha-bravo-charlie",
                f"{second_key}=delta-echo-foxtrot",
                f"{third_key}=real-example-production-value",
            )
        )

        result = redact_text(source)

        self.assertEqual(result.counts["GENERIC_SECRET"], 3)
        self.assertNotIn("alpha-bravo-charlie", result.text)
        self.assertNotIn("real-example-production-value", result.text)

    def test_redaction_is_idempotent(self) -> None:
        key = "auth_" + "token"
        value = "super-" + "secret-" + "value"
        first = redact_text(f"{key}={value}\n")
        second = redact_text(first.text)

        self.assertEqual(second.text, first.text)
        self.assertEqual(second.total, 0)

    def test_url_credentials_are_removed(self) -> None:
        url_value = "very-private-" + "password"
        scheme = "postgres" + "ql"
        username = "db" + "user"
        source = f"DATABASE_URL={scheme}://{username}:{url_value}@localhost/app\n"
        result = redact_text(source)

        self.assertNotIn(url_value, result.text)
        self.assertIn("CONTEXTCOURIER_REDACTED:URL_PASSWORD", result.text)

    def test_pgp_private_key_block_is_removed(self) -> None:
        begin = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
        end = "-----END PGP " + "PRIVATE KEY BLOCK-----"
        synthetic_body = ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789+/" * 2) + "="
        source = f"{begin}\n\n{synthetic_body}\n{end}\n"

        result = redact_text(source)

        self.assertNotIn(synthetic_body, result.text)
        self.assertEqual(result.counts["PGP_PRIVATE_KEY"], 1)

    def test_pem_private_key_block_is_removed(self) -> None:
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        body = ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n" * 2)
        result = redact_text(f"{begin}\n{body}{end}\n")

        self.assertNotIn(body, result.text)
        self.assertEqual(result.counts["PRIVATE_KEY"], 1)

    def test_authorization_placeholders_and_prose_are_not_redacted(self) -> None:
        header = "Author" + "ization: Bearer " + "YOUR_TOKEN_HERE"
        prose = "Basic authentication is documented here."
        source = f"{header}\n{prose}\n"

        result = redact_text(source)

        self.assertEqual(result.text, source)
        self.assertEqual(result.total, 0)

    def test_percent_prefixed_real_value_is_not_treated_as_placeholder(self) -> None:
        key = "pass" + "word"
        source = f"{key}=%real-production-value\n"

        result = redact_text(source)

        self.assertEqual(result.counts["GENERIC_SECRET"], 1)

    def test_docker_auth_json_value_is_redacted(self) -> None:
        key = "au" + "th"
        value = "dXNlcjpwYXNzd29yZA=="
        source = f'{{"{key}": "{value}"}}\n'

        result = redact_text(source)

        self.assertNotIn(value, result.text)
        self.assertEqual(result.counts["DOCKER_AUTH"], 1)

    def test_framework_secret_keys_and_real_your_prefix_are_redacted(self) -> None:
        first_key = "SECRET_KEY" + "_BASE"
        second_key = "RAILS_MASTER" + "_KEY"
        third_key = "pass" + "word"
        source = "\n".join(
            (
                f"{first_key}=rails-production-secret-value",
                f"{second_key}=master-production-secret-value",
                f"{third_key}=your_actual_production_value_12345",
            )
        )
        result = redact_text(source)

        self.assertEqual(result.counts["GENERIC_SECRET"], 3)
        self.assertNotIn("rails-production-secret-value", result.text)
        self.assertNotIn("your_actual_production_value", result.text)

    def test_maven_password_element_is_redacted(self) -> None:
        value = "maven-production-password"
        result = redact_text(f"<server><password>{value}</password></server>\n")

        self.assertEqual(result.counts["XML_SECRET"], 1)
        self.assertNotIn(value, result.text)
        self.assertIn("<password><<CONTEXTCOURIER_REDACTED:XML_SECRET>></password>", result.text)


if __name__ == "__main__":
    unittest.main()
