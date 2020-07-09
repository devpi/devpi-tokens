from devpi_common.types import cached_property
from functools import lru_cache
from pluggy import HookimplMarker
from pyramid.compat import is_nonstr_iter
from pyramid.security import Everyone
import argon2
import base64
import pymacaroons
import secrets


server_hookimpl = HookimplMarker("devpiserver")


def generate_token_id():
    return "".join(
        secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        for x in range(8))


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

    def new_token(self, user):
        token_user = user.name
        token_info = dict(
            key=secrets.token_urlsafe(32))
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
        return macaroon.serialize()

    def verify(self, macaroon, token_info):
        key = self.derive_key(token_info["key"])
        return self.verifier.verify(macaroon, key)


def devpi_token_utility(request):
    result = request.registry.get("devpi_token_utility")
    if result is None:
        result = TokenUtility(request.registry["xom"])
        request.registry["devpi_token_utility"] = result
    return result


@server_hookimpl
def devpiserver_get_credentials(request):
    authorization = getattr(request, "authorization", None)
    if not authorization:
        return None
    if authorization.authtype.lower() != "bearer":
        return None
    try:
        tu = request.devpi_token_utility
        macaroon = tu.deserialize(authorization.params)
        (token_user, token_id) = tu.token_user_id(macaroon)
    except Exception:
        # if token isn't a valid macaroon, then we don't care
        return None
    return (token_user, authorization.params)


@server_hookimpl
def devpiserver_auth_request(request, userdict, username, password):
    try:
        tu = request.devpi_token_utility
        macaroon = tu.deserialize(password)
        (token_user, token_id) = tu.token_user_id(macaroon)
    except Exception:
        # if password isn't a valid macaroon, then we don't care
        return None
    if token_user != username:
        return dict(status="reject")
    tokens = userdict.get("tokens", {})
    if token_id not in tokens:
        return dict(status="reject")
    try:
        tu.verify(macaroon, tokens[token_id])
        # XXX this is a bit hacky until Pyramid 2.0
        request.devpi_macaroon = macaroon
        return dict(status="ok")
    except Exception:
        return dict(status="reject")


@server_hookimpl
def devpiserver_auth_denials(request, acl, user, stage):
    denials = None
    macaroon = getattr(request, "devpi_macaroon", None)
    if macaroon:
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
    config.scan("devpi_tokens.views")


@server_hookimpl
def devpiserver_pyramid_configure(config, pyramid_config):
    # by using include, the package name doesn't need to be set explicitly
    # for registrations of static views etc
    pyramid_config.include("devpi_tokens.server")
