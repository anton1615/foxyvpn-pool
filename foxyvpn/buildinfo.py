"""Build metadata, analogous to the original Go ``cmd/proxy/buildinfo.go``.

``BUILD_COMMIT`` and ``BUILD_DATE`` are placeholders that a release pipeline
may overwrite; they default to "unknown" for editable/source installs.
"""

from __future__ import annotations

__version__ = "1.0.2"
BUILD_COMMIT = "a1426f86d381cf73909f8713d922d2bd1c168dfa"
BUILD_DATE = "2026-09-01T10:24:42Z"


def version_string() -> str:
    return f"foxyvpn {__version__} (commit {BUILD_COMMIT}, built {BUILD_DATE})"
