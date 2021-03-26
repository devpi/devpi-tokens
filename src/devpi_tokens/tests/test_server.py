from devpi_common.url import URL
import pytest
try:
    from devpi_server import __version__  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-server installed")
else:
    from test_devpi_server.conftest import gentmp  # noqa
    from test_devpi_server.conftest import httpget  # noqa
    from test_devpi_server.conftest import lower_argon2_parameters  # noqa
    from test_devpi_server.conftest import makemapp  # noqa
    from test_devpi_server.conftest import maketestapp  # noqa
    from test_devpi_server.conftest import makexom  # noqa
    from test_devpi_server.conftest import mapp  # noqa
    from test_devpi_server.conftest import pypiurls  # noqa
    from test_devpi_server.conftest import storage_info  # noqa
    from test_devpi_server.conftest import testapp  # noqa

    (makexom, mapp, testapp)  # shut up pyflakes


@pytest.fixture
def xom(request, makexom):
    import devpi_tokens.server
    xom = makexom(plugins=[
        (devpi_tokens.server, None)])
    return xom


@pytest.fixture
def app(xom):
    app = xom.create_app()
    while not hasattr(app, "registry"):
        app = app.app
    return app


@pytest.fixture
def makerequest(app):
    from devpi_server.log import threadlog
    from pyramid.request import Request
    from pyramid.request import apply_request_extensions

    def makerequest(*args, **kwargs):
        request = Request.blank(*args, **kwargs)
        request.registry = app.registry
        request.log = threadlog
        apply_request_extensions(request, extensions=app.request_extensions)
        return request

    return makerequest


def test_get_identity(makerequest, xom):
    from devpi_tokens.server import TokenIdentity
    request = makerequest("/")
    assert request.identity is None
    request = makerequest("/")
    request.headers["Authorization"] = ""
    assert request.identity is None
    request = makerequest("/")
    request.headers["Authorization"] = "Bearer"
    assert request.identity is None
    with xom.keyfs.transaction(write=True):
        user = xom.model.create_user("foo", "")
        token = request.devpi_token_utility.new_token(user)
        request = makerequest("/")
        request.headers["Authorization"] = "Bearer %s" % token
        assert isinstance(request.identity, TokenIdentity)
        assert request.identity.username == "foo"
        assert request.identity.groups == []


def test_auth_request(makerequest, xom):
    from pyramid.authentication import b64encode
    import secrets
    request = makerequest("/")
    assert request.authenticated_userid is None
    request = makerequest("/")
    request.headers["Authorization"] = ""
    assert request.authenticated_userid is None
    request = makerequest("/")
    request.headers["Authorization"] = "Bearer"
    assert request.authenticated_userid is None
    with xom.keyfs.transaction(write=True):
        user = xom.model.create_user("foo", "")
        token = request.devpi_token_utility.new_token(user)
        request = makerequest("/")
        request.headers["Authorization"] = "Bearer %s" % token
        assert request.authenticated_userid == "foo"
        with user.key.update() as userdict:
            (token_id,) = userdict["tokens"].keys()
            userdict["tokens"][token_id]["key"] = secrets.token_urlsafe(32)
        request = makerequest("/")
        assert request.authenticated_userid is None
        with user.key.update() as userdict:
            (token_id,) = userdict["tokens"].keys()
            del userdict["tokens"][token_id]
        request = makerequest("/")
        assert request.authenticated_userid is None
        with user.key.update() as userdict:
            del userdict["tokens"]
        request = makerequest("/")
        assert request.authenticated_userid is None
        basic_auth = "bar:%s" % token
        basic = b64encode(basic_auth).decode('ascii')
        request = makerequest("/")
        request.headers["Authorization"] = "Basic %s" % basic
        assert request.authenticated_userid is None
        basic_auth = "bar:foo"
        basic = b64encode(basic_auth).decode('ascii')
        request = makerequest("/")
        request.headers["Authorization"] = "Basic %s" % basic
        assert request.authenticated_userid is None


def test_login_with_token_as_password(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url)
    token = r.json['result']['token']
    mapp.logout()
    mapp.login(api.user, token, code=401)
    assert mapp.auth is None
    # now explicitly check for error message
    r = testapp.post_json(
        api.login,
        {"user": api.user, "password": token},
        expect_errors=True)
    assert r.status_code == 401
    assert "could not be authenticated" in r.json['message']


def test_login_with_token_as_password_and_mismatched_user(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url)
    username = api.user + 'foo'
    token = r.json['result']['token']
    mapp.logout()
    mapp.login(username, token, code=401)
    assert mapp.auth is None
    # now explicitly check for error message
    r = testapp.post_json(
        api.login,
        {"user": username, "password": token},
        expect_errors=True)
    assert r.status_code == 401
    assert "could not be authenticated" in r.json['message']


def test_token_user_permissions(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url)
    token = r.json['result']['token']
    mapp.logout()
    # with no login it should be denied
    testapp.post(url, code=403)
    # with token authentication it should also be denied
    headers = dict(authorization="Bearer %s" % token)
    testapp.post(
        url, headers=headers, code=403)
    # as well as deletion
    r = testapp.delete('/' + api.user, headers=headers, expect_errors=True)
    assert r.status_code == 403
