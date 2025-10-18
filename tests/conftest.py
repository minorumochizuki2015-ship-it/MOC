import os
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
photo_src = os.path.join(root, "PhotoApp", "src")
if os.path.isdir(photo_src) and photo_src not in sys.path:
    sys.path.insert(0, photo_src)


def pytest_configure():  # type: ignore[missing-return-type-doc]
    """Set a fixed UTC timestamp for deterministic tests.

    When running the test suite we want timestamps derived from
    datetime.datetime.now()/utcnow() to be stable. The sitecustomize module
    added in the project root monkey-patches datetime when the FIXED_UTC
    environment variable is present.  Here we ensure the variable is set to a
    known value unless the user/CI already provided one.
    """

    os.environ.setdefault("FIXED_UTC", "2024-01-01T00:00:00Z")
