from contextlib import closing
from devpi_common.url import URL
from devpi_tokens.restrictions import AllowedRestriction
from devpi_tokens.restrictions import IndexesRestriction
from devpi_tokens.restrictions import ProjectsRestriction
from devpi_tokens.restrictions import get_restrictions_from_macaroon
from devpi_tokens.restrictions import get_restrictions_from_token
from time import sleep
import pytest
import requests
import shutil
import socket
import subprocess
import sys
try:
    from devpi_server import __version__ as __server_version__  # noqa: F401
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-server installed")
try:
    from devpi import __version__ as __client_version__  # noqa: F401
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-client installed")


@pytest.fixture
def capfd(capfd):
    from _pytest.pytester import LineMatcher

    def readouterr_matcher():
        result = capfd.readouterr()
        out = LineMatcher(result.out.splitlines())
        err = LineMatcher(result.err.splitlines())
        return (out, err)

    capfd.readouterr_matcher = readouterr_matcher
    return capfd


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
        for arg in ["devpi", "--clientdir", clientdir, *args]:
            callargs.append(str(arg.url if isinstance(arg, URL) else arg))
        print("*** inline$ %s" % " ".join(callargs))
        hub, method = initmain(callargs)
        monkeypatch.setattr(hub, "ask_confirm", ask_confirm)
        expected = kwargs.get("code")
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
        return s.getsockname()[1]
    return None


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
    path = shutil.which("devpi-server")
    init_path = shutil.which("devpi-init")
    assert path
    args = [
        "--serverdir", str(serverdir)]
    try:
        subprocess.check_call(
            [str(init_path), *args, '--no-root-pypi'])
    except subprocess.CalledProcessError as e:
        # this won't output anything on Windows
        print(
            getattr(e, 'output', "Can't get process output on Windows"),
            file=sys.stderr)
        raise
    p = subprocess.Popen(
        [str(path), *args, "--debug", "--host", host, "--port", str(port)])
    wait_for_server_api(host, port)
    return (p, URL("http://%s:%s" % (host, port)))


@pytest.fixture(scope="session")
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


def test_token_create(capfd, devpi):
    import pymacaroons
    devpi("token-create")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    assert token.startswith("devpi-")
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    assert token_user.startswith("user")
    assert get_restrictions_from_macaroon(macaroon).names == ["expires"]


def test_token_create_allowed(capfd, devpi):
    import pymacaroons
    devpi("token-create", "-a", "pkg_read", "--allowed=toxresult_upload , pypi_submit")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    assert token_user.startswith("user")
    restrictions = get_restrictions_from_macaroon(macaroon)
    assert restrictions.names == ["allowed", "expires"]
    (allowed,) = restrictions["allowed"]
    assert allowed == AllowedRestriction(["toxresult_upload", "pkg_read", "pypi_submit"])
    devpi("token-inspect", "--token", token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines("*id*: %s" % token_id)
    out.fnmatch_lines("*restriction*: allowed=pkg_read,pypi_submit,toxresult_upload")
    devpi("token-list")
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines([
        "    %s" % token_id,
        "        restrictions:",
        "            allowed=pkg_read,pypi_submit,toxresult_upload",
        "            expires=*"])


def test_token_create_indexes(capfd, devpi):
    import pymacaroons
    devpi("token-create", "-i", "foo", "--indexes=bar , ham")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    assert token_user.startswith("user")
    restrictions = get_restrictions_from_macaroon(macaroon)
    assert restrictions.names == ["expires", "indexes"]
    (indexes,) = restrictions["indexes"]
    assert indexes == IndexesRestriction(["bar", "foo", "ham"])
    devpi("token-inspect", "--token", token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines("*id*: %s" % token_id)
    out.fnmatch_lines("*restriction*: indexes=bar,foo,ham")
    devpi("token-list")
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines([
        "    %s" % token_id,
        "        restrictions:",
        "            expires=*",
        "            indexes=bar,foo,ham"])


def test_token_create_projects(capfd, devpi):
    import pymacaroons
    devpi("token-create", "-p", "foo", "--projects=bar , ham")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    assert token_user.startswith("user")
    restrictions = get_restrictions_from_macaroon(macaroon)
    assert restrictions.names == ["expires", "projects"]
    (projects,) = restrictions["projects"]
    assert projects == ProjectsRestriction(["bar", "foo", "ham"])
    devpi("token-inspect", "--token", token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines("*id*: %s" % token_id)
    out.fnmatch_lines("*restriction*: projects=bar,foo,ham")
    devpi("token-list")
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines([
        "    %s" % token_id,
        "        restrictions:",
        "            expires=*",
        "            projects=bar,foo,ham"])


def test_token_derive(capfd, devpi):
    devpi("token-create")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    devpi("token-derive", "--token", token)
    (out, err) = capfd.readouterr()
    assert "No restrictions provided" in out
    devpi("token-derive", "--token", token, "-e", "1 day")
    (out, err) = capfd.readouterr()
    new_token = out.splitlines()[-1]
    (expires, new_expires) = get_restrictions_from_token(new_token)
    assert new_expires < expires
    devpi("token-inspect", "--token", new_token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines([
        "*restriction*: expires=*",
        "*restriction*: expires=*"])
    devpi("token-derive", "--token", token, "-i", "bar")
    (out, err) = capfd.readouterr()
    new_token = out.splitlines()[-1]
    (expires, indexes) = get_restrictions_from_token(new_token)
    assert indexes == IndexesRestriction(["bar"])
    devpi("token-inspect", "--token", new_token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines([
        "*restriction*: expires=*",
        "*restriction*: indexes=bar"])


def test_token_inspect_from_file(capfd, devpi, devpi_username, tmp_path):
    devpi("token-create")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    token_path = tmp_path.joinpath("token")
    token_path.write_text(token)
    devpi("token-inspect", "-f", str(token_path))
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines([
        f"*user*: {devpi_username}",
        "*id*: *",
        "*restriction*: expires=*"])


def test_token_list(capfd, devpi):
    from devpi_tokens.client import pymacaroons
    devpi("token-create")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    devpi("token-list")
    (out, err) = capfd.readouterr()
    assert ("Tokens for '%s':" % token_user) in out
    assert "    %s" % token_id in out
    devpi("token-delete", token_id)
    (out, err) = capfd.readouterr()
    assert ("token %s deleted" % token_id) in out
    devpi("token-list")
    (out, err) = capfd.readouterr()
    assert ("No tokens for '%s'" % token_user) in out


def test_token_login(capfd, devpi):
    devpi("token-create")
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


def test_login_with_token_as_password_user_permissions(capfd, devpi, devpi_username):
    devpi("token-create")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    devpi("logout")
    (out, err) = capfd.readouterr()
    assert "login information deleted" in out
    devpi("use")
    (out, err) = capfd.readouterr()
    assert "not logged in" in out
    devpi("login", "--password", token, devpi_username)
    (out, err) = capfd.readouterr()
    assert '401 Unauthorized' in out
    assert 'could not be authenticated' in out


def test_login_deleted_token(capfd, devpi):
    from devpi_tokens.client import pymacaroons
    devpi("token-create")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    devpi("token-delete", token_id)
    (out, err) = capfd.readouterr()
    assert ("token %s deleted" % token_id) in out
    devpi("logout")
    (out, err) = capfd.readouterr()
    assert "login information deleted" in out
    devpi("use")
    (out, err) = capfd.readouterr()
    assert "not logged in" in out
    devpi("token-login", "--token", token)
    (out, err) = capfd.readouterr()
    assert ("The token id %s doesn't exist" % token_id) in out


def test_token_for_other_user_forbidden(capfd, devpi, devpi_username):
    other_user = devpi_username + "_other"
    devpi("user", "-c", other_user, "password=123", "email=123")
    devpi("token-create", "--user", other_user)
    (out, err) = capfd.readouterr()
    assert "403 Forbidden: Access was denied to this resource." in out
    assert "Unauthorized: user_token_create failed permission check" in out


def test_root_user_can_create_other_tokens(capfd, devpi, devpi_username):
    from devpi_tokens.client import pymacaroons
    devpi("login", "root", "--password", "")
    (out, err) = capfd.readouterr()
    assert "logged in 'root'" in out
    devpi("token-create", "-u", devpi_username)
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    assert token_user == devpi_username
    devpi("token-list", "-u", devpi_username)
    (out, err) = capfd.readouterr()
    assert ("Tokens for '%s':" % token_user) in out
    assert "    %s" % token_id in out


def test_root_create_expiration(capfd, devpi, devpi_username):
    from devpi_tokens.client import pymacaroons
    devpi("login", "root", "--password", "")
    (out, err) = capfd.readouterr()
    assert "logged in 'root'" in out
    devpi("token-create", "-u", devpi_username, "-e", "never")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id1) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    assert token_user == devpi_username
    devpi("token-inspect", "--token", token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines("*id*: %s" % token_id1)
    out.fnmatch_lines("*restriction*: expires=never")
    devpi("token-create", "-u", devpi_username, "-e", "3 years")
    (out, err) = capfd.readouterr()
    token = out.splitlines()[-1]
    macaroon = pymacaroons.Macaroon.deserialize(token[6:])
    (token_user, token_id2) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    assert token_user == devpi_username
    devpi("token-inspect", "--token", token)
    (out, err) = capfd.readouterr_matcher()
    out.fnmatch_lines("*id*: %s" % token_id2)
    out.fnmatch_lines("*restriction*: expires=*")
    devpi("token-list", "-u", devpi_username)
    (out, err) = capfd.readouterr_matcher()
    token_lines = {
        token_id1: [
            "    %s" % token_id1,
            "        restrictions:",
            "            expires=never"],
        token_id2: [
            "    %s" % token_id2,
            "        restrictions:",
            "            expires=*"]}
    lines = ["Tokens for '%s':" % token_user]
    # the output of token-list is ordered by token id, so we have
    # to have the test in the correct order as well
    for k in sorted(token_lines):
        lines.extend(token_lines[k])
    out.fnmatch_lines(lines)
