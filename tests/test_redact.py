from __future__ import annotations

import time
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

    def test_url_placeholder_components_are_preserved(self) -> None:
        source = "DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@localhost/app\n"

        result = redact_text(source)

        self.assertEqual(result.text, source)
        self.assertEqual(result.total, 0)

    def test_password_only_and_token_username_urls_are_redacted(self) -> None:
        password = "redis-production-password"
        token = "repository-access-token-value"
        source = (
            f"CACHE_URL=redis://:{password}@localhost/0\n"
            f"REMOTE_URL=https://{token}:@example.invalid/repo.git\n"
        )

        result = redact_text(source)

        self.assertNotIn(password, result.text)
        self.assertNotIn(token, result.text)
        self.assertEqual(result.counts["URL_CREDENTIALS"], 2)
        self.assertIn("CONTEXTCOURIER_REDACTED:URL_PASSWORD", result.text)
        self.assertIn("CONTEXTCOURIER_REDACTED:URL_USERNAME", result.text)

    def test_url_credential_longer_than_legacy_boundary_is_redacted(self) -> None:
        password = "p" * 513
        result = redact_text(f"CACHE_URL=redis://:{password}@localhost/0\n")

        self.assertNotIn(password, result.text)
        self.assertEqual(result.counts["URL_CREDENTIALS"], 1)

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

    def test_pem_private_key_with_short_final_line_is_removed(self) -> None:
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\nQUJD\n"

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

    def test_quoted_authorization_values_are_redacted(self) -> None:
        header_value = "production-bearer-value-12345"
        source = (
            f'{{"Authorization": "Bearer {header_value}"}}\n'
            f"Authorization: 'Basic {header_value}'\n"
        )
        result = redact_text(source)

        self.assertNotIn(header_value, result.text)
        self.assertEqual(result.counts["AUTHORIZATION"], 2)
        self.assertIn('"Authorization": "Bearer <<CONTEXTCOURIER_REDACTED:AUTHORIZATION>>"', result.text)

    def test_short_valid_basic_authorization_is_redacted(self) -> None:
        source = 'Authorization: "Basic dTpw"\n'

        result = redact_text(source)

        self.assertNotIn("dTpw", result.text)
        self.assertEqual(result.counts["AUTHORIZATION"], 1)

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

    def test_npm_auth_token_assignment_is_redacted_after_rename(self) -> None:
        key = "_auth" + "Token"
        value = "npm-production-credential"
        source = f"//registry.example.invalid/:{key}={value}\n"

        result = redact_text(source)

        self.assertNotIn(value, result.text)
        self.assertEqual(result.counts["GENERIC_SECRET"], 1)

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

    def test_long_namespaced_sensitive_key_is_redacted(self) -> None:
        key = "alpha_beta_gamma_delta_epsilon_service_api_key"
        value = "production-credential-value"

        result = redact_text(f"{key}={value}\n")

        self.assertNotIn(value, result.text)
        self.assertEqual(result.counts["GENERIC_SECRET"], 1)

    def test_hierarchical_and_camel_case_sensitive_keys_are_redacted(self) -> None:
        value = "production-credential-value"
        long_prefix = "a" * 40
        source = "\n".join(
            (
                f"MYAPP__PASSWORD={value}",
                f"{long_prefix}_PASSWORD={value}",
                f'{{"dbPassword": "{value}"}}',
                f'{{"serviceApiKey": "{value}"}}',
            )
        )

        result = redact_text(source)

        self.assertNotIn(value, result.text)
        self.assertEqual(result.counts["GENERIC_SECRET"], 4)

    def test_pwd_assignment_variants_are_redacted(self) -> None:
        value = "database-production-password"
        source = f'DB_PWD={value}\n{{"pwd": "{value}"}}\n'

        result = redact_text(source)

        self.assertNotIn(value, result.text)
        self.assertEqual(result.counts["GENERIC_SECRET"], 2)

    def test_short_high_confidence_container_values_are_redacted(self) -> None:
        source = (
            'password="abc"\n'
            '<password>q</password>\n'
            '{"auth": "dTpw"}\n'
        )

        result = redact_text(source)

        self.assertNotIn('"abc"', result.text)
        self.assertNotIn(">q<", result.text)
        self.assertNotIn('"dTpw"', result.text)
        self.assertEqual(result.counts["GENERIC_SECRET"], 1)
        self.assertEqual(result.counts["XML_SECRET"], 1)
        self.assertEqual(result.counts["DOCKER_AUTH"], 1)

    def test_maven_password_element_is_redacted(self) -> None:
        value = "maven-production-password"
        result = redact_text(f"<server><password>{value}</password></server>\n")

        self.assertEqual(result.counts["XML_SECRET"], 1)
        self.assertNotIn(value, result.text)
        self.assertIn("<password><<CONTEXTCOURIER_REDACTED:XML_SECRET>></password>", result.text)

    def test_placeholder_prefix_and_default_expressions_are_not_exempted(self) -> None:
        key = "pass" + "word"
        cases = (
            f'{key}="${{SAFE_REFERENCE}}literal-value"\n',
            f'{key}="${{SAFE_REFERENCE:-hardcoded-fallback}}"\n',
            f'{key}="{{{{ value | default(\'hardcoded-fallback\') }}}}"\n',
        )
        for source in cases:
            with self.subTest(source=source):
                result = redact_text(source)
                self.assertEqual(result.counts["GENERIC_SECRET"], 1)
                self.assertNotEqual(result.text, source)

    def test_multiline_sensitive_assignments_remove_the_entire_value(self) -> None:
        canary = "multiline-production-credential"
        cases = (
            f'password = """\n{canary}\nsecond-line\n"""\n',
            f"password = '''\n{canary}\nsecond-line\n'''\n",
            f"password: |\n  {canary}\n  second-line\nnext: safe\n",
            f"password: >-\n  {canary}\n  second-line\nnext: safe\n",
        )
        for source in cases:
            with self.subTest(source=source):
                result = redact_text(source)
                self.assertNotIn(canary, result.text)
                self.assertNotIn("second-line", result.text)
                self.assertEqual(result.counts["GENERIC_SECRET"], 1)

    def test_escaped_quotes_cannot_leave_a_secret_suffix(self) -> None:
        canary = "escaped-quote-secret-suffix"
        cases = (
            f'{{"password": "prefix\\\"{canary}"}}\n',
            f'password = "prefix\\\"{canary}"\n',
            f"password: 'prefix''{canary}'\n",
            f'password = """prefix\\\"""{canary}\n"""\n',
        )
        for source in cases:
            with self.subTest(source=source):
                result = redact_text(source)
                self.assertNotIn(canary, result.text)
                self.assertEqual(result.counts["GENERIC_SECRET"], 1)

    def test_bare_secret_punctuation_suffix_is_fully_removed(self) -> None:
        canary = "punctuation-secret-suffix"
        key = "pass" + "word"
        for separator in ("#", "]", "}", ",", ";"):
            source = f"{key}=prefix{separator}{canary}\n"
            with self.subTest(separator=separator):
                result = redact_text(source)
                self.assertNotIn(canary, result.text)
                self.assertEqual(result.counts["GENERIC_SECRET"], 1)

    def test_code_references_are_not_mistaken_for_literal_secrets(self) -> None:
        source = (
            "_source_token: str | None = field(default=None)\n"
            "return cls(_source_token=source_token)\n"
            "password = match.group(\"password\")\n"
            "safe_password = password if password_safe else replacement\n"
        )

        result = redact_text(source)

        self.assertEqual(result.text, source)
        self.assertEqual(result.total, 0)

    def test_putty_private_key_body_is_removed_and_huge_count_is_safe(self) -> None:
        body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"
        source = (
            "PuTTY-User-Key-File-3: ssh-rsa\n"
            "Encryption: none\n"
            "Comment: synthetic\n"
            "Public-Lines: 1\n"
            f"{body}\n"
            "Private-Lines: 1\n"
            f"{body}\n"
            "Private-MAC: 00000000\n"
        )

        result = redact_text(source)

        self.assertEqual(result.counts["PUTTY_PRIVATE_KEY"], 1)
        self.assertEqual(result.text.count(body), 1)
        huge = "Private-Lines: " + ("9" * 5000) + "\n"
        self.assertEqual(redact_text(source.replace("Private-Lines: 1\n", huge)).total, 0)

    def test_adversarial_detector_inputs_complete_within_a_generous_bound(self) -> None:
        samples = (
            ("a-" * 40_000) + "z",
            ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + ("A" * 64) + "\n") * 500,
        )
        started = time.monotonic()
        for sample in samples:
            redact_text(sample)
        self.assertLess(time.monotonic() - started, 3.0)


if __name__ == "__main__":
    unittest.main()
