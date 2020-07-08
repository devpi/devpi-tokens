import pytest
try:
    from devpi_server import __version__  # noqa
except ImportError:
    pytestmark = pytest.mark.skip("No devpi-server installed")
else:
    from test_devpi_server.conftest import gentmp  # noqa
    from test_devpi_server.conftest import httpget  # noqa
    from test_devpi_server.conftest import lower_argon2_parameters  # noqa
    from test_devpi_server.conftest import maketestapp  # noqa
    from test_devpi_server.conftest import makexom  # noqa
    from test_devpi_server.conftest import pypiurls  # noqa
    from test_devpi_server.conftest import storage_info  # noqa
    from test_devpi_server.conftest import testapp  # noqa

    (makexom, testapp)  # shut up pyflakes


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


def test_get_credentials(makerequest, xom):
    request = makerequest("/")
    assert request.unauthenticated_userid is None
    request.headers["Authorization"] = ""
    assert request.unauthenticated_userid is None
    request.headers["Authorization"] = "Bearer"
    assert request.unauthenticated_userid is None
    with xom.keyfs.transaction(write=True):
        user = xom.model.create_user("foo", "")
        token = request.devpi_token_utility.new_token(user)
        request.headers["Authorization"] = "Bearer %s" % token
        assert request.unauthenticated_userid == "foo"


def test_auth_request(makerequest, xom):
    from pyramid.authentication import b64encode
    import secrets
    request = makerequest("/")
    assert request.authenticated_userid is None
    request.headers["Authorization"] = ""
    assert request.authenticated_userid is None
    request.headers["Authorization"] = "Bearer"
    assert request.authenticated_userid is None
    with xom.keyfs.transaction(write=True):
        user = xom.model.create_user("foo", "")
        token = request.devpi_token_utility.new_token(user)
        request.headers["Authorization"] = "Bearer %s" % token
        assert request.authenticated_userid == "foo"
        with user.key.update() as userdict:
            (token_id,) = userdict["tokens"].keys()
            userdict["tokens"][token_id]["key"] = secrets.token_urlsafe(32)
        assert request.authenticated_userid is None
        with user.key.update() as userdict:
            (token_id,) = userdict["tokens"].keys()
            del userdict["tokens"][token_id]
        assert request.authenticated_userid is None
        with user.key.update() as userdict:
            del userdict["tokens"]
        assert request.authenticated_userid is None
        basic_auth = "bar:%s" % token
        basic = b64encode(basic_auth).decode('ascii')
        request.headers["Authorization"] = "Basic %s" % basic
        assert request.authenticated_userid is None
        basic_auth = "bar:foo"
        basic = b64encode(basic_auth).decode('ascii')
        request.headers["Authorization"] = "Basic %s" % basic
        assert request.authenticated_userid is None
