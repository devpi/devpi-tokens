from contextlib import closing
from devpi_common.url import URL
from time import sleep
import py
import pytest
import requests
import socket
import subprocess
import sys
try:
    from devpi_server import __version__  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-server installed")
try:
    from devpi import __version__  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-client installed")


@pytest.fixture
def cmd_devpi(tmpdir, monkeypatch):
    """ execute devpi subcommand in-process (with fresh init) """
    from devpi.main import initmain

    def ask_confirm(msg):
        print("%s: yes" % msg)
        return True

    clientdir = tmpdir.join("client")

    def run_devpi(*args, **kwargs):
        callargs = []
        for arg in ["devpi", "--clientdir", clientdir] + list(args):
            if isinstance(arg, URL):
                arg = arg.url
            callargs.append(str(arg))
        print("*** inline$ %s" % " ".join(callargs))
        hub, method = initmain(callargs)
        monkeypatch.setattr(hub, "ask_confirm", ask_confirm)
        expected = kwargs.get("code", None)
        try:
            method(hub, hub.args)
        except SystemExit as sysex:
            hub.sysex = sysex
            if expected is None or expected < 0 or expected >= 400:
                # we expected an error or nothing, don't raise
                pass
            else:
                raise
        finally:
            hub.close()
        if expected is not None:
            if expected == -2:  # failed-to-start
                assert hasattr(hub, "sysex")
            elif isinstance(expected, list):
                assert hub._last_http_stati == expected
            else:
                if not isinstance(expected, tuple):
                    expected = (expected, )
                if hub._last_http_status not in expected:
                    pytest.fail(
                        "got http code %r, expected %r" % (
                            hub._last_http_status, expected))
        return hub

    run_devpi.clientdir = clientdir
    return run_devpi


def get_open_port(host):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind((host, 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def wait_for_port(host, port, timeout=60):
    while timeout > 0:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                return timeout
        sleep(1)
        timeout -= 1
    raise RuntimeError(
        "The port %s on host %s didn't become accessible" % (port, host))


def wait_for_server_api(host, port, timeout=60):
    timeout = wait_for_port(host, port, timeout=timeout)
    while timeout > 0:
        try:
            r = requests.get("http://%s:%s/+api" % (host, port), timeout=1)
        except requests.exceptions.ConnectionError:
            pass
        else:
            if r.status_code == 200:
                return
        sleep(1)
        timeout -= 1
    raise RuntimeError(
        "The api on port %s, host %s didn't become accessible" % (port, host))


def _liveserver(serverdir):
    host = 'localhost'
    port = get_open_port(host)
    path = py.path.local.sysfind("devpi-server")
    init_path = py.path.local.sysfind("devpi-init")
    assert path
    args = [
        "--serverdir", str(serverdir)]
    try:
        subprocess.check_call(
            [str(init_path)] + args + ['--no-root-pypi'])
    except subprocess.CalledProcessError as e:
        # this won't output anything on Windows
        print(
            getattr(e, 'output', "Can't get process output on Windows"),
            file=sys.stderr)
        raise
    p = subprocess.Popen(
        [str(path)] + args + ["--debug", "--host", host, "--port", str(port)])
    wait_for_server_api(host, port)
    return (p, URL("http://%s:%s" % (host, port)))


@pytest.yield_fixture(scope="session")
def url_of_liveserver(request):
    serverdir = request.config._tmpdirhandler.mktemp("liveserver")
    (p, url) = _liveserver(serverdir)
    try:
        yield url
    finally:
        p.terminate()
        p.wait()


@pytest.fixture
def devpi_username():
    attrname = '_count'
    count = getattr(devpi_username, attrname, 0)
    setattr(devpi_username, attrname, count + 1)
    return "user%d" % count


@pytest.fixture
def devpi(cmd_devpi, devpi_username, url_of_liveserver):
    cmd_devpi("use", url_of_liveserver.url, code=200)
    cmd_devpi("user", "-c", devpi_username, "password=123", "email=123")
    cmd_devpi("login", devpi_username, "--password", "123")
    return cmd_devpi


def test_create_token(capfd, devpi):
    import pymacaroons
    devpi("create-token")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token)
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    assert token_user.startswith("user")


def test_token_login(capfd, devpi):
    devpi("create-token")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    devpi("logout")
    (out, err) = capfd.readouterr()
    assert "login information deleted" in out
    devpi("use")
    (out, err) = capfd.readouterr()
    assert "not logged in" in out
    devpi("token-login", "--token", token)
    (out, err) = capfd.readouterr()
    assert "logged in 'user" in out
    devpi("use")
    (out, err) = capfd.readouterr()
    assert "logged in as user" in out
