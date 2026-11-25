"""
Mask secrets (access tokens, passwords, keys) before they reach the logs.

Calrissian and cwltool log the workflow inputs and each pod spec at debug level.
These contain the user's workspace access tokens. Everything Calrissian writes to
stderr is collected by the platform log pipeline, so secrets must be removed first.

``install_log_redaction`` replaces the logging record factory, so every log record
from every logger is masked when it is created. This does not depend on which
handlers are attached. That matters because cwltool's ``main()`` removes its
default handler and adds a new one when the run starts.

Two layers mask secrets:

- By value: the values of secret-named workflow inputs in the params file (for
  example the STS credentials in ``AWS_SECRET_ACCESS_KEY``) are masked wherever
  they appear, in any format. This covers secrets that have no fixed shape, such
  as AWS keys passed to a step as ``--flag value`` or as a pod env var.
- By pattern: JWTs, bearer tokens and ``name=value`` pairs with a secret name.

Output from the tool (step) pods is not changed in the step log files. Lines that
Calrissian repeats into its own log are masked like any other log record.
"""
import logging
import os
import re

import yaml

REDACTED = "***REDACTED***"

# The workflow inputs. The platform mounts them here. job.py reads the tokens from
# the same file, so keep this the only copy of the path.
PARAMS_PATH = "/workflow-params/params.yml"

# Shorter values are not masked by value: they could match ordinary text.
_MIN_SECRET_VALUE_LENGTH = 8

# Names whose values are secret. Bare "key" is left out because free text uses it
# for harmless things (cache keys, dict keys). The text on each side of the secret
# word is capped at 64 characters. With an unbounded ``*``, a long unbroken run such
# as a base64 blob makes the regex take quadratic time (seconds per log line).
_SECRET_NAME = r"[\w.-]{0,64}(?:token|secret|password|passwd|credential|api[_-]?key|access[_-]?key|private[_-]?key)[\w.-]{0,64}"

# A JWT: three base64url segments, the first one a JSON header ("eyJ" = '{"').
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

# "Authorization: Bearer <token>" and similar.
_BEARER_RE = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)

# name: value / name=value / "name": "value", for secret names.
# (?<![\w.-]) starts a match only at the start of a name, not inside a long run.
_KEY_VALUE_RE = re.compile(
    r"""(?P<prefix>(?P<q1>["']?)(?<![\w.-])""" + _SECRET_NAME + r"""(?P=q1)\s*[:=]\s*)"""
    r"""(?:(?P<q2>["'])(?P<quoted>[^"'\n]*)(?P=q2)|(?P<bare>[^\s,;{}\[\]"']+))""",
    re.IGNORECASE,
)

_SECRET_NAME_RE = re.compile(_SECRET_NAME, re.IGNORECASE)

_exc_formatter = logging.Formatter()

# Known secret values and one regex that matches any of them (None when empty).
_secret_values = set()
_secret_values_re = None


def add_secret_values(values):
    """Mask these exact strings in all log text from now on."""
    global _secret_values_re
    new = {v for v in values if isinstance(v, str) and len(v) >= _MIN_SECRET_VALUE_LENGTH}
    if not new - _secret_values:
        return
    _secret_values.update(new)
    # Longest first, so a value that contains another one is masked whole.
    ordered = sorted(_secret_values, key=len, reverse=True)
    _secret_values_re = re.compile("|".join(re.escape(v) for v in ordered))


def forget_secret_values():
    """Clear the known secret values (for tests)."""
    global _secret_values_re
    _secret_values.clear()
    _secret_values_re = None


def load_secret_values(params_path=PARAMS_PATH):
    """
    Register the values of secret-named top-level inputs in the params file.
    A missing or unreadable file is ignored (for example a local run).
    """
    if not os.path.exists(params_path):
        return
    try:
        with open(params_path, "r") as f:
            params = yaml.safe_load(f)
    except Exception:
        logging.getLogger(__name__).warning("Could not read %s to find secret inputs", params_path)
        return
    if isinstance(params, dict):
        add_secret_values(
            value for name, value in params.items()
            if isinstance(name, str) and _SECRET_NAME_RE.fullmatch(name)
        )


def _mask_key_value(match):
    if match.group("q2"):
        # Keep empty values visible: knowing a token was *not* set helps debugging.
        if not match.group("quoted"):
            return match.group(0)
        return "{0}{1}{2}{1}".format(match.group("prefix"), match.group("q2"), REDACTED)
    return match.group("prefix") + REDACTED


def redact_text(text):
    """Return ``text`` with secret-looking values replaced by ``REDACTED``."""
    if not isinstance(text, str) or not text:
        return text
    if _secret_values_re is not None:
        text = _secret_values_re.sub(REDACTED, text)
    text = _JWT_RE.sub(REDACTED, text)
    text = _BEARER_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _KEY_VALUE_RE.sub(_mask_key_value, text)
    return text


def redact_record(record):
    """
    Mask secrets in the message, traceback and stack info of a log record.

    This runs inside the caller's ``log.*()`` call, so it must never raise. If
    masking fails, the record keeps only a short note: the unmasked text could
    hold a secret, so it is not logged.
    """
    try:
        try:
            message = record.getMessage()
        except Exception:  # a bad format string must not lose the log line
            message = str(record.msg)
        record.msg = redact_text(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = _exc_formatter.formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
    except Exception as e:
        record.msg = "[log message hidden: secret masking failed ({})]".format(type(e).__name__)
        record.args = None
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
    return record


def install_log_redaction(params_path=PARAMS_PATH):
    """
    Mask secrets in every log record in this process. Safe to call more than once.

    Reads the secret input values from ``params_path`` first, so that they are
    masked by value. Records are only created for enabled levels, so this adds
    no work for debug messages when debug logging is off.
    """
    load_secret_values(params_path)
    current = logging.getLogRecordFactory()
    if getattr(current, "redacts_secrets", False):
        return

    def redacting_factory(*args, **kwargs):
        return redact_record(current(*args, **kwargs))

    redacting_factory.redacts_secrets = True
    logging.setLogRecordFactory(redacting_factory)
