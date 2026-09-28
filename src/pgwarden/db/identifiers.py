"""Safe quoting for identifiers and literals embedded in generated DDL.

DDL (``CREATE ROLE``, ``ALTER ROLE``, ``GRANT``, ...) cannot use bind
parameters, so role, schema and bundle names have to be interpolated into
SQL text. Config already constrains those names with a regex before they
reach here (see :mod:`pgwarden.config`); quoting is defense in depth on top
of that, not a substitute for it.
"""

from __future__ import annotations


def quote_ident(name: str) -> str:
    """Double-quote a Postgres identifier, doubling any embedded quotes."""
    return '"' + name.replace('"', '""') + '"'


def quote_literal(value: str) -> str:
    """Single-quote a Postgres string literal, doubling any embedded quotes."""
    return "'" + value.replace("'", "''") + "'"
