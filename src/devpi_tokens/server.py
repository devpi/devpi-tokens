from devpi_common.types import cached_property
from functools import lru_cache
from pluggy import HookimplMarker
from pyramid.authorization import Everyone
from pyramid.httpexceptions import HTTPForbidden
from pyramid.httpexceptions import HTTPNotFound
from pyramid.util import is_nonstr_iter
import argon2
import base64
import pymacaroons
import secrets
import time
import traceback


server_hookimpl = HookimplMarker("devpiserver")


def generate_token_id():
    return "".join(
        secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        for x in range(8))


class InvalidMacaroon(Exception):
    pass


class Caveat:
    def __init__(self, request, verifier):
        self.request = request
        self.context = getattr(request, "context", None)
        if self.context is None:
            self.context = getattr(request, "root", None)
        self.verifier = verifier

    def __call__(self, predicate):
        raise InvalidMacaroon()


class V1Caveat(Caveat):
    def verify_expires(self, value):
        if value == "never":
            return True
        try:
            expires = int(value)
        except Exception:
            expires = 0
        if time.time() >= expires:
            raise InvalidMacaroon("Token expired at %s" % value)
        return True

    def verify_indexes(self, value):
        if self.context is None:
            return True
        username = self.context.username
        index = self.context.index
        if username is None or index is None:
            return True
        indexname = "%s/%s" % (username, index)
        indexes = {x.strip() for x in value.split(',')}
        if indexname not in indexes:
            raise InvalidMacaroon("Token denied access to index '%s'" % indexname)
        return True

    def __call__(self, predicate):
        (key, value) = predicate.split("=", 1)
        verify = getattr(self, "verify_%s" % key, None)
        if verify is None:
            raise InvalidMacaroon("Unknown caveat '%s'" % key)
        return verify(value)


class TokenUtility:
    def __init__(self, xom):
        self.xom = xom
        self.verifier = pymacaroons.Verifier()
        self.derive_key = lru_cache(maxsize=128)(self._derive_key)

    @cached_property
    def tokens_secret(self):
        return self.xom.config.get_derived_key(b"devpi-tokens")

    @property
    def _secret_parameters(self):
        return argon2.Parameters(
            type=argon2.low_level.Type.ID,
            version=argon2.low_level.ARGON2_VERSION,
            salt_len=16,
            hash_len=16,
            time_cost=2,
            memory_cost=102400,
            parallelism=8)

    def _derive_key(self, key):
        secret_parameters = self._secret_parameters
        return argon2.low_level.hash_secret_raw(
            self.tokens_secret,
            base64.urlsafe_b64decode(key + "==="),
            time_cost=secret_parameters.time_cost,
            memory_cost=secret_parameters.memory_cost,
            parallelism=secret_parameters.parallelism,
            hash_len=secret_parameters.hash_len,
            type=secret_parameters.type,
            version=secret_parameters.version)

    def deserialize(self, token):
        return pymacaroons.Macaroon.deserialize(token)

    def token_user_id(self, macaroon):
        return macaroon.identifier.decode("ascii").rsplit("-", 1)

    def get_tokens_info(self, user):
        tokens_info = {}
        userdict = user.get(credentials=True)
        for token_id, token_info in userdict.get("tokens", {}).items():
            if isinstance(token_info, dict):
                token_info = dict(token_info)
            else:
                token_info = dict()
            token_info.pop("key", None)
            tokens_info[token_id] = token_info
        return tokens_info

    def new_token(self, user, restrictions=()):
        token_user = user.name
        restrictions = [x.dump() for x in restrictions]
        token_info = dict(
            key=secrets.token_urlsafe(32),
            restrictions=restrictions)
        with user.key.update() as userdict:
            tokens = userdict.setdefault("tokens", {})
            while 1:
                token_id = generate_token_id()
                if token_id not in tokens:
                    break
            tokens[token_id] = token_info
        macaroon = pymacaroons.Macaroon(
            identifier="%s-%s" % (token_user, token_id),
            key=self.derive_key(token_info["key"]),
            version=pymacaroons.MACAROON_V2)
        for restriction in restrictions:
            macaroon.add_first_party_caveat(restriction)
        return macaroon.serialize()

    def remove_token(self, user, token_id):
        if token_id not in self.get_tokens_info(user):
            raise HTTPNotFound("No token with id %s" % token_id)
        with user.key.update() as userdict:
            del userdict["tokens"][token_id]

    def verify(self, request, macaroon, token_info):
        key = self.derive_key(token_info["key"])
        self.verifier.satisfy_general(V1Caveat(request, self.verifier))
        return self.verifier.verify(macaroon, key)


def devpi_token_utility(request):
    result = request.registry.get("devpi_token_utility")
    if result is None:
        result = TokenUtility(request.registry["xom"])
        request.registry["devpi_token_utility"] = result
    return result


class TokenIdentity:
    def __init__(self, username, macaroon):
        self.username = username
        self.groups = []
        self.macaroon = macaroon


@server_hookimpl
def devpiserver_get_identity(request, credentials):
    authorization = getattr(request, "authorization", None)
    if authorization is not None:
        if authorization.authtype.lower() == "bearer":
            credentials = (None, authorization.params)
    if credentials is None:
        return None
    try:
        tu = request.devpi_token_utility
        macaroon = tu.deserialize(credentials[1])
        (token_user, token_id) = tu.token_user_id(macaroon)
    except Exception:
        # if token isn't a valid macaroon, then we don't care
        return None
    if credentials[0] is not None and credentials[0] != token_user:
        raise HTTPForbidden("Token doesn't match user name")
    model = request.registry["xom"].model
    user = model.get_user(token_user)
    if user is None:
        raise HTTPForbidden("User for token doesn't exist")
    tokens = user.get(credentials=True).get("tokens", {})
    if token_id not in tokens:
        raise HTTPForbidden("The token id %s doesn't exist" % token_id)
    try:
        tu.verify(request, macaroon, tokens[token_id])
    except Exception as e:  # https://github.com/ecordell/pymacaroons/issues/50
        msg = "".join(traceback.format_exception_only(e.__class__, e))
        raise HTTPForbidden("Exception during token verification: %s" % msg)
    return TokenIdentity(token_user, credentials[1])


@server_hookimpl
def devpiserver_auth_denials(request, acl, user, stage):
    identity = request.identity
    if identity is None or not isinstance(identity, TokenIdentity):
        return None
    # with a token the user can't be modified, so for instance no new
    # tokens can be created
    denials = set()
    for ace_action, ace_principal, ace_permissions in acl:
        if not is_nonstr_iter(ace_permissions):
            ace_permissions = [ace_permissions]
        for ace_permission in ace_permissions:
            if ace_permission.startswith("user_"):
                denials.add((Everyone, ace_permission))
    return denials


def includeme(config):
    config.add_request_method(devpi_token_utility, reify=True)
    config.add_route("user-token-create", "/{user}/+token-create")
    config.add_route("user-token-delete", "/{user}/+tokens/{id}")
    config.add_route("user-tokens", "/{user}/+tokens")
    config.scan("devpi_tokens.views")


@server_hookimpl
def devpiserver_pyramid_configure(config, pyramid_config):
    # by using include, the package name doesn't need to be set explicitly
    # for registrations of static views etc
    pyramid_config.include("devpi_tokens.server")
