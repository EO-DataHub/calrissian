import base64
import io
import json
import logging
from unittest import TestCase

import os
import tempfile

import yaml

from calrissian.redact import (
    REDACTED,
    forget_secret_values,
    install_log_redaction,
    load_secret_values,
    redact_text,
)


def _b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


# A made-up JWT with the same shape as a Keycloak access token. Not a real token.
FAKE_JWT = "{}.{}.{}".format(
    _b64({"alg": "RS256", "typ": "JWT", "kid": "test"}),
    _b64({"sub": "user", "preferred_username": "test-user", "exp": 1}),
    "c2lnbmF0dXJlLW5vdC1yZWFs_-0123456789",
)


class RedactTextTestCase(TestCase):

    def test_masks_jwt_anywhere(self):
        text = "inputs {{\"x\": \"{}\"}} and {} again".format(FAKE_JWT, FAKE_JWT)
        result = redact_text(text)
        self.assertNotIn("eyJ", result)
        self.assertEqual(result.count(REDACTED), 2)

    def test_masks_bearer_token(self):
        result = redact_text("Authorization: Bearer abc.def-123")
        self.assertEqual(result, "Authorization: Bearer " + REDACTED)

    def test_masks_sensitive_name_value_pairs(self):
        cases = {
            '"WORKSPACE_ACCESS_TOKEN": "opaque-value"': '"WORKSPACE_ACCESS_TOKEN": "{}"'.format(REDACTED),
            "CALLING_WORKSPACE_ACCESS_TOKEN: opaque-value": "CALLING_WORKSPACE_ACCESS_TOKEN: " + REDACTED,
            "db_password=hunter2 next": "db_password=" + REDACTED + " next",
            "{'aws_secret_access_key': 'abc'}": "{{'aws_secret_access_key': '{}'}}".format(REDACTED),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(redact_text(text), expected)

    def test_keeps_harmless_text(self):
        for text in [
            "Building resources spec from {'cores': 1, 'ram': 256}",
            "[job foo] keydictstr is {} -> abc123",
            '"WORKSPACE_ACCESS_TOKEN": ""',
            "pod name job-123 has status OOMKilled",
        ]:
            with self.subTest(text=text):
                self.assertEqual(redact_text(text), text)

    def test_non_strings_pass_through(self):
        self.assertIsNone(redact_text(None))
        self.assertEqual(redact_text(""), "")


# Made-up STS-style credentials (the secret key is AWS's documentation example).
AWS_KEY_ID = "ASIAEXAMPLEEXAMPLE12"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION = "IQoJb3JpZ2luX2VjEXAMPLEsessiontoken/+abc=="


class SecretValuesTestCase(TestCase):
    """Secret input values from params.yml are masked in any format."""

    def setUp(self):
        forget_secret_values()
        handle, self.params_path = tempfile.mkstemp(suffix=".yml")
        with os.fdopen(handle, "w") as f:
            yaml.safe_dump({
                "WORKSPACE_ACCESS_TOKEN": FAKE_JWT,
                "AWS_ACCESS_KEY_ID": AWS_KEY_ID,
                "AWS_SECRET_ACCESS_KEY": AWS_SECRET,
                "AWS_SESSION_TOKEN": AWS_SESSION,
                "calling_workspace": "my-workspace-name",
                "aws_region": "eu-west-2",
                "short_token": "abc",
                "null_secret": "null",
                "max_tokens": 512,
            }, f)
        load_secret_values(self.params_path)

    def tearDown(self):
        forget_secret_values()
        os.remove(self.params_path)

    def assert_no_aws_secret(self, text):
        result = redact_text(text)
        for value in (AWS_KEY_ID, AWS_SECRET, AWS_SESSION):
            self.assertNotIn(value, result)
        return result

    def test_masks_values_in_pod_spec_env(self):
        dumped = yaml.dump({"env": [
            {"name": "AWS_SECRET_ACCESS_KEY", "value": AWS_SECRET},
            {"name": "AWS_SESSION_TOKEN", "value": AWS_SESSION},
            {"name": "AWS_ACCESS_KEY_ID", "value": AWS_KEY_ID},
        ]})
        result = self.assert_no_aws_secret(dumped)
        self.assertIn("name: AWS_SECRET_ACCESS_KEY", result)

    def test_masks_values_passed_as_flags(self):
        args = "python run.py --aws-access-key-id {} --aws-secret-access-key {} --aws-session-token {}".format(
            AWS_KEY_ID, AWS_SECRET, AWS_SESSION)
        result = self.assert_no_aws_secret(yaml.dump({"args": [args]}))
        self.assertIn("--aws-secret-access-key", result)

    def test_masks_values_under_renamed_inputs(self):
        self.assert_no_aws_secret(json.dumps({"creds": AWS_SECRET, "key_id": AWS_KEY_ID, "sess": AWS_SESSION}))

    def test_keeps_values_of_other_inputs(self):
        text = "calling_workspace my-workspace-name in eu-west-2, abc, null, 512"
        self.assertEqual(redact_text(text), text)

    def test_missing_params_file_is_ignored(self):
        load_secret_values(self.params_path + ".missing")


class InstallLogRedactionTestCase(TestCase):
    """The record factory is global, so each test restores it."""

    def setUp(self):
        # tests/__init__.py turns logging off for the whole suite; these tests need it on.
        self.disabled_level = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.original_factory = logging.getLogRecordFactory()
        install_log_redaction()
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        self.logger = logging.getLogger("calrissian.test_redact")
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.logger.removeHandler(self.handler)
        self.logger.propagate = True
        logging.setLogRecordFactory(self.original_factory)
        logging.disable(self.disabled_level)

    def test_masks_formatted_args(self):
        self.logger.debug("[workflow ] inputs %s", json.dumps({"WORKSPACE_ACCESS_TOKEN": FAKE_JWT}, indent=4))
        output = self.stream.getvalue()
        self.assertNotIn(FAKE_JWT, output)
        self.assertIn(REDACTED, output)
        self.assertTrue(output.startswith("DEBUG [workflow ] inputs"))

    def test_masks_traceback(self):
        try:
            raise ValueError("bad input " + FAKE_JWT)
        except ValueError:
            self.logger.exception("failed")
        output = self.stream.getvalue()
        self.assertIn("ValueError", output)
        self.assertNotIn(FAKE_JWT, output)

    def test_bad_format_string_keeps_line(self):
        self.logger.info("50%% done %s %s", "only-one-arg")
        self.assertIn("done", self.stream.getvalue())

    def test_install_reads_secret_values_from_params(self):
        handle, params_path = tempfile.mkstemp(suffix=".yml")
        with os.fdopen(handle, "w") as f:
            yaml.safe_dump({"AWS_SECRET_ACCESS_KEY": AWS_SECRET}, f)
        try:
            install_log_redaction(params_path)
            self.logger.debug("[pod] python run.py --aws-secret-access-key %s", AWS_SECRET)
        finally:
            forget_secret_values()
            os.remove(params_path)
        self.assertNotIn(AWS_SECRET, self.stream.getvalue())
        self.assertIn("--aws-secret-access-key " + REDACTED, self.stream.getvalue())

    def test_install_is_idempotent(self):
        factory = logging.getLogRecordFactory()
        install_log_redaction()
        self.assertIs(logging.getLogRecordFactory(), factory)

    def test_handler_added_later_is_covered(self):
        """cwltool's main() swaps its handler for a new coloredlogs one. Reproduce that."""
        import coloredlogs
        from cwltool.loghandler import _logger as cwltool_logger, defaultStreamHandler

        stream = io.StringIO()
        handlers, level, propagate = list(cwltool_logger.handlers), cwltool_logger.level, cwltool_logger.propagate
        cwltool_logger.propagate = False
        cwltool_logger.removeHandler(defaultStreamHandler)
        # cwltool's configure_logging() sets the handler to DEBUG when run with --debug.
        coloredlogs.install(logger=cwltool_logger, stream=stream, level=logging.DEBUG)
        cwltool_logger.setLevel(logging.DEBUG)
        try:
            cwltool_logger.debug("[workflow ] inputs %s", json.dumps({"WORKSPACE_ACCESS_TOKEN": FAKE_JWT}))
        finally:
            for handler in list(cwltool_logger.handlers):
                cwltool_logger.removeHandler(handler)
            for handler in handlers:
                cwltool_logger.addHandler(handler)
            cwltool_logger.setLevel(level)
            cwltool_logger.propagate = propagate
        self.assertIn("[workflow ] inputs", stream.getvalue())
        self.assertNotIn(FAKE_JWT, stream.getvalue())


class ActivateLoggingTestCase(TestCase):
    """activate_logging() changes global logging state, so restore all of it."""

    LOGGERS = ["calrissian.{}".format(name) for name in ["executor", "context", "tool", "job", "k8s", "main"]]

    def setUp(self):
        self.original_factory = logging.getLogRecordFactory()
        self.original_state = {
            name: (list(logging.getLogger(name).handlers), logging.getLogger(name).level)
            for name in self.LOGGERS
        }

    def tearDown(self):
        logging.setLogRecordFactory(self.original_factory)
        for name, (handlers, level) in self.original_state.items():
            logger = logging.getLogger(name)
            logger.handlers[:] = handlers
            logger.setLevel(level)

    def test_activate_logging_installs_redaction(self):
        from calrissian.main import activate_logging

        activate_logging(logging.DEBUG)
        self.assertTrue(getattr(logging.getLogRecordFactory(), "redacts_secrets", False))


class StepLogsUnchangedTestCase(TestCase):

    def test_step_log_entry_is_not_redacted(self):
        """Users already see their own step output, so the step log files keep it as is."""
        from calrissian.k8s import KubernetesClient

        entry = KubernetesClient.format_log_entry("pod", "max_tokens=512 " + FAKE_JWT)
        self.assertEqual(entry["entry"], "max_tokens=512 " + FAKE_JWT)


class RedactRecordFailureTestCase(TestCase):

    def test_failure_hides_message_and_does_not_raise(self):
        from unittest.mock import patch
        from calrissian import redact

        try:
            raise ValueError("bad " + FAKE_JWT)
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "token %s", (FAKE_JWT,), exc_info)
        with patch.object(redact, "redact_text", side_effect=RuntimeError("boom")):
            result = redact.redact_record(record)

        self.assertEqual(result.getMessage(), "[log message hidden: secret masking failed (RuntimeError)]")
        self.assertIsNone(result.exc_info)
        self.assertIsNone(result.exc_text)
        self.assertNotIn(FAKE_JWT, logging.Formatter().format(result))


class RedactTextSpeedTestCase(TestCase):
    """Long unbroken runs once made the name pattern take quadratic time."""

    def test_long_unbroken_lines_are_fast(self):
        import time
        for text in [base64.urlsafe_b64encode(os.urandom(30000)).decode(), "a-" * 20000]:
            start = time.monotonic()
            redact_text(text)
            # The quadratic-time bug took several seconds; 2s leaves room for slow CI.
            self.assertLess(time.monotonic() - start, 2)

    def test_long_names_still_match(self):
        for text in ['"CALLING_WORKSPACE_ACCESS_TOKEN": "opaque-value"', "STAGE_AWS_SECRET_ACCESS_KEY=opaque-value"]:
            with self.subTest(text=text):
                self.assertNotIn("opaque-value", redact_text(text))
