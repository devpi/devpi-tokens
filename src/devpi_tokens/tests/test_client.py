import pytest
try:
    import devpi.main
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-client installed")


def test_commands(capsys):
    with pytest.raises(SystemExit) as e:
        devpi.main.main(['devpi', '--help'])
    (out, err) = capsys.readouterr()
    assert e.value.code == 0
    assert 'token-create' in out
    assert 'token-delete' in out
    assert 'token-derive' in out
    assert 'token-inspect' in out
    assert 'token-list' in out
    assert 'token-login' in out


def test_user_permissions_hidden(capsys):
    with pytest.raises(SystemExit) as e:
        devpi.main.main(['devpi', 'token-create', '--help'])
    (out, err) = capsys.readouterr()
    assert e.value.code == 0
    assert 'comma separated list of allowed permissions' in out
    assert 'user_create' not in out
    assert 'user_delete' not in out
    assert 'user_login' not in out
    assert 'user_modify' not in out


def test_get_expires_from_args():
    from devpi_tokens.client import get_expires_from_args
    import time

    class args:
        expires = '10s'

    now = int(time.time())
    result = get_expires_from_args(None, args)
    assert 9 <= (result - now) <= 11


def test_get_not_before_from_args():
    from devpi_tokens.client import get_not_before_from_args
    import time

    class args:
        not_before = '-10s'

    now = int(time.time())
    result = get_not_before_from_args(None, args)
    assert 9 <= (now - result) <= 11
