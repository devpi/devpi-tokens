from devpi_server.views import apireturn
from pyramid.view import view_config
import pymacaroons
import secrets


@view_config(
    route_name="user-token-create",
    request_method="POST",
    permission="user_modify")
def user_token_create(context, request):
    token_user = context.user.name
    key = secrets.token_urlsafe(32)
    with context.user.key.update() as userdict:
        tokens = userdict.setdefault("tokens", {})
        while 1:
            token_id = "".join(
                secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                for x in range(8))
            if token_id not in tokens:
                break
        tokens[token_id] = key
    result = dict(
        token=pymacaroons.Macaroon(
            identifier="%s-%s" % (token_user, token_id),
            key=key,
            version=pymacaroons.MACAROON_V2).serialize())
    apireturn(200, type="token-info", result=result)
