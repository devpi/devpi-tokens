from devpi_common.url import URL
from devpi_tokens.restrictions import ExpiresRestriction
from devpi_tokens.restrictions import IndexesRestriction
from devpi_tokens.restrictions import get_restrictions_from_macaroon
from devpi_tokens.restrictions import get_restrictions_from_token
from pluggy import HookimplMarker
import json
import pymacaroons
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

    (makexom, makemapp, maketestapp, mapp, testapp)  # shut up pyflakes


devpiserver_hookimpl = HookimplMarker("devpiserver")


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
    from pyramid.httpexceptions import HTTPForbidden
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
        with pytest.raises(HTTPForbidden) as e:
            request.authenticated_userid
        assert e.value.code == 403
        assert e.value.args == ("Token doesn't match user name",)
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


def test_token_delete(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath("+token-create").url
    r = testapp.post(url)
    token = r.json["result"]["token"]
    macaroon = pymacaroons.Macaroon.deserialize(token)
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    url = URL(api.index).joinpath("+tokens", token_id).url
    r = testapp.delete(url)
    assert r.json["message"] == "token %s deleted" % token_id


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


def test_create_token_expiration(mapp, testapp):
    import time
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    # invalid
    r = testapp.post(url, json.dumps(dict(expires="invalid")), code=400)
    assert r.json["message"] == "Invalid value 'invalid' for expiration"
    # not before current time
    r = testapp.post(url, json.dumps(dict(expires=10)), code=400)
    assert r.json["message"] == "Can't set expiration before current time"
    # not more than a year
    r = testapp.post(url, json.dumps(dict(expires=int(time.time() + 31536001))), code=403)
    assert r.json["message"] == "Not allowed to set expiration to more than one year"
    # just 10 seconds
    r = testapp.post(url, json.dumps(dict(expires=int(time.time() + 10))))
    macaroon = pymacaroons.Macaroon.deserialize(r.json["result"]["token"])
    assert get_restrictions_from_macaroon(macaroon).names == ["expires"]
    # "never" not allowed by regular users
    r = testapp.post(url, json.dumps(dict(expires="never")), code=403)
    assert r.json["message"] == "Not allowed to create token with no expiration"


def test_token_expiration(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url)
    token = r.json['result']['token']
    # add a shorter expiration to a new derived token
    macaroon = pymacaroons.Macaroon.deserialize(token)
    macaroon.add_first_party_caveat("expires=10")
    (orig_expires, new_expires) = get_restrictions_from_macaroon(macaroon)["expires"]
    assert new_expires == ExpiresRestriction(10)
    r = testapp.xget(
        403,
        URL(api.index).joinpath('+api').url,
        headers=dict(Authorization="Bearer %s" % macaroon.serialize()))
    assert "InvalidMacaroon: Token expired at 10" in r.text


def test_root_can_create_never_expiring_tokens(mapp, testapp):
    api = mapp.create_and_use()
    mapp.login("root", "")
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url, json.dumps(dict(expires="never")))
    token = r.json['result']['token']
    macaroon = pymacaroons.Macaroon.deserialize(token)
    (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit("-", 1)
    assert api.user == token_user
    (expires,) = get_restrictions_from_macaroon(macaroon)["expires"]
    assert expires == ExpiresRestriction("never")
    testapp.xget(
        200,
        URL(api.index).joinpath('+api').url,
        headers=dict(Authorization="Bearer %s" % token))


def test_create_token_indexes(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    # not a list
    r = testapp.post(url, json.dumps(dict(indexes="")), code=400)
    # list with empty item
    r = testapp.post(url, json.dumps(dict(indexes=[""])), code=400)
    assert r.json["message"] == "Empty item at position 1 in indexes list"
    # list with non string item
    r = testapp.post(url, json.dumps(dict(indexes=[0])), code=400)
    assert r.json["message"] == "Item at position 1 is not a string in indexes list"
    # sorting
    r = testapp.post(url, json.dumps(dict(indexes=["foo", "bar"])))
    (expires, indexes) = get_restrictions_from_token(r.json['result']['token'])
    assert indexes == IndexesRestriction(["bar", "foo"])


def test_token_indexes(mapp, testapp):
    api1 = mapp.create_and_use()
    api2 = mapp.create_index('other')
    url = URL(api1.index).joinpath('+token-create').url
    r = testapp.post(url)
    token = r.json['result']['token']
    # add an indexes limitation to a new derived token
    macaroon = pymacaroons.Macaroon.deserialize(token)
    macaroon.add_first_party_caveat("indexes=%s" % api1.stagename)
    # we can patch our first index
    assert testapp.get(api1.index).json["result"]["volatile"] is True
    r = testapp.patch_json(
        api1.index, ["volatile=False"],
        headers=dict(Authorization="Bearer %s" % macaroon.serialize()))
    assert r.status_code == 200
    assert testapp.get(api1.index).json["result"]["volatile"] is False
    # but not the second one
    assert testapp.get(api2.index).json["result"]["volatile"] is True
    r = testapp.patch_json(
        api2.index, ["volatile=False"],
        expect_errors=True,
        headers=dict(Authorization="Bearer %s" % macaroon.serialize()))
    assert r.status_code == 403
    assert (
        "InvalidMacaroon: Token denied access to index 'user1/other'") in r.text
    assert testapp.get(api2.index).json["result"]["volatile"] is True
    # the token without limitation can
    r = testapp.patch_json(
        api2.index, ["volatile=False"],
        headers=dict(Authorization="Bearer %s" % token))
    assert r.status_code == 200
    assert testapp.get(api2.index).json["result"]["volatile"] is False


def test_token_projects(mapp, testapp):
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url)
    token = r.json['result']['token']
    # add a projects limitation to a new derived token
    macaroon = pymacaroons.Macaroon.deserialize(token)
    macaroon.add_first_party_caveat("projects=pkg,hello")
    mapp.testapp.auth = mapp.auth = (mapp.auth[0], macaroon.serialize())
    content_hello = mapp.makepkg("hello-1.0.tar.gz", b"hello", "hello", "1.0")
    mapp.upload_file_pypi("hello-1.0.tar.gz", content_hello, "hello", "1.0")
    content_pkg = mapp.makepkg("pkg-1.0.tar.gz", b"pkg", "pkg", "1.0")
    mapp.upload_file_pypi("pkg-1.0.tar.gz", content_pkg, "pkg", "1.0")
    # can't upload other
    content_other = mapp.makepkg("other-1.0.tar.gz", b"other", "other", "1.0")
    mapp.upload_file_pypi("other-1.0.tar.gz", content_other, "other", "1.0", code=403)
    # but original token can
    mapp.testapp.auth = mapp.auth = (mapp.auth[0], token)
    mapp.upload_file_pypi("other-1.0.tar.gz", content_other, "other", "1.0")


def test_token_projects_forbidden_plugin(makemapp, maketestapp, makexom):
    import devpi_tokens.server

    class Plugin:
        @devpiserver_hookimpl
        def devpiserver_authcheck_forbidden(self, request):
            # we only need to trigger user verification here to let token
            # validation run
            request.authenticated_userid

    plugin = Plugin()
    xom = makexom(plugins=[devpi_tokens.server, plugin])
    testapp = maketestapp(xom)
    mapp = makemapp(testapp)
    api = mapp.create_and_use()
    url = URL(api.index).joinpath('+token-create').url
    r = testapp.post(url)
    token = r.json['result']['token']
    # add a projects limitation to a new derived token
    macaroon = pymacaroons.Macaroon.deserialize(token)
    macaroon.add_first_party_caveat("projects=pkg,hello")
    mapp.testapp.auth = mapp.auth = (mapp.auth[0], macaroon.serialize())
    content_hello = mapp.makepkg("hello-1.0.tar.gz", b"hello", "hello", "1.0")
    mapp.upload_file_pypi("hello-1.0.tar.gz", content_hello, "hello", "1.0")
    content_pkg = mapp.makepkg("pkg-1.0.tar.gz", b"pkg", "pkg", "1.0")
    mapp.upload_file_pypi("pkg-1.0.tar.gz", content_pkg, "pkg", "1.0")
    # can't upload other
    content_other = mapp.makepkg("other-1.0.tar.gz", b"other", "other", "1.0")
    mapp.upload_file_pypi("other-1.0.tar.gz", content_other, "other", "1.0", code=403)
    assert mapp.getpkglist() == ["hello", "pkg"]
    # but original token can
    mapp.testapp.auth = mapp.auth = (mapp.auth[0], token)
    mapp.upload_file_pypi("other-1.0.tar.gz", content_other, "other", "1.0")
    assert mapp.getpkglist() == ["hello", "other", "pkg"]
    # try accessing project data via /+authcheck,
    # as plain devpi-server doesn't check permissions here
    mapp.testapp.auth = mapp.auth = (mapp.auth[0], macaroon.serialize())
    testapp.xget(200, "/+authcheck", headers={"X-Original-URI": "/%s/pkg" % api.stagename})
    testapp.xget(200, "/+authcheck", headers={"X-Original-URI": "/%s/+simple/pkg" % api.stagename})
    testapp.xget(403, "/+authcheck", headers={"X-Original-URI": "/%s/other" % api.stagename})
    testapp.xget(403, "/+authcheck", headers={"X-Original-URI": "/%s/+simple/other" % api.stagename})
    # original token can
    mapp.testapp.auth = mapp.auth = (mapp.auth[0], token)
    testapp.xget(200, "/+authcheck", headers={"X-Original-URI": "/%s/pkg" % api.stagename})
    testapp.xget(200, "/+authcheck", headers={"X-Original-URI": "/%s/+simple/pkg" % api.stagename})
    testapp.xget(200, "/+authcheck", headers={"X-Original-URI": "/%s/other" % api.stagename})
    testapp.xget(200, "/+authcheck", headers={"X-Original-URI": "/%s/+simple/other" % api.stagename})
