"""Secret loading: environment variables with a `*_FILE` alternative.

Every secret pgwarden reads (role HMAC secret, signing key, session secret,
OIDC client secret, Slack webhook URL, SMTP URL, the state DSN) can be
supplied either directly as an environment variable or as a path to a file
holding the value, named ``<VAR>_FILE``. This mirrors the convention used by
Docker secrets and Cloud Run secret volumes. Supplying both forms for the
same variable is a configuration error, since it is ambiguous which one
should win.
"""

from __future__ import annotations

import os


class SecretError(RuntimeError):
    """Raised when a secret is missing or ambiguously configured."""


def read_secret(name: str, *, required: bool = True, default: str | None = None) -> str | None:
    """Read a secret from ``name`` or from the file named by ``<name>_FILE``.

    Exactly one of the two environment variables may be set. The file
    variant is read as UTF-8 text and has at most one trailing newline
    stripped (the common shape of a value written by ``echo`` or a secret
    manager), leaving any other trailing whitespace untouched.

    Returns ``default`` (``None`` unless given) when neither is set and
    ``required`` is False. Raises :class:`SecretError` when neither is set
    and ``required`` is True, when both are set, or when the file cannot be
    read.
    """
    env_value = os.environ.get(name)
    file_path = os.environ.get(f"{name}_FILE")

    if env_value is not None and file_path is not None:
        raise SecretError(f"both {name} and {name}_FILE are set; unset one of them")

    if env_value is not None:
        return env_value

    if file_path is not None:
        try:
            with open(file_path, encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            raise SecretError(f"cannot read {name}_FILE ({file_path}): {exc}") from exc
        if content.endswith("\n"):
            content = content[:-1]
        return content

    if required:
        raise SecretError(f"{name} (or {name}_FILE) is required but not set")
    return default
