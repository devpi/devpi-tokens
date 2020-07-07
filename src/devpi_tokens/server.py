from pluggy import HookimplMarker
import pymacaroons


server_hookimpl = HookimplMarker("devpiserver")


@server_hookimpl
def devpiserver_get_credentials(request):
    authorization = getattr(request, "authorization", None)
    if not authorization:
        return None
    if authorization.authtype.lower() != "bearer":
        return None
    try:
        macaroon = pymacaroons.Macaroon.deserialize(authorization.params)
        (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    except Exception:
        # if token isn't a valid macaroon, then we don't care
        return None
    return (token_user, authorization.params)


@server_hookimpl
def devpiserver_auth_user(userdict, username, password):
    try:
        macaroon = pymacaroons.Macaroon.deserialize(password)
        (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    except Exception:
        # if password isn't a valid macaroon, then we don't care
        return None
    if token_user != username:
        return dict(status="reject")
    tokens = userdict.get("tokens", {})
    if token_id not in tokens:
        return dict(status="reject")
    key = tokens[token_id]
    verifier = pymacaroons.Verifier()
    if not verifier.verify(macaroon, key):
        return dict(status="reject")
    return dict(status="ok")


def includeme(config):
    config.add_route("user-token-create", "/{user}/+token-create")
    config.scan("devpi_tokens.views")


@server_hookimpl
def devpiserver_pyramid_configure(config, pyramid_config):
    # by using include, the package name doesn't need to be set explicitly
    # for registrations of static views etc
    pyramid_config.include("devpi_tokens.server")
