import pytest
try:
    import devpi.main  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-client installed")
