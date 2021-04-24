import pytest
try:
    import devpi.main  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-client installed")


def test_commands(capsys):
    with pytest.raises(SystemExit) as e:
        devpi.main.main(['devpi', '--help'])
    (out, err) = capsys.readouterr()
    assert e.value.code == 0
    assert 'token-create' in out
    assert 'token-inspect' in out
    assert 'token-login' in out
