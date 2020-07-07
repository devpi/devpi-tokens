import pytest
try:
    from devpi_server import __version__  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-server installed")
