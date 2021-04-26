from devpi_server.views import apireturn
from devpi_tokens.restrictions import get_restrictions_from_request
from pyramid.view import view_config


@view_config(
    route_name="user-token-create",
    request_method="POST",
    permission="user_modify")
def user_token_create(context, request):
    tu = request.devpi_token_utility
    restrictions = get_restrictions_from_request(request)
    result = dict(
        token=tu.new_token(context.user, restrictions))
    apireturn(200, type="token-info", result=result)


@view_config(
    route_name="user-token-delete",
    request_method="DELETE",
    permission="user_modify")
def user_token_delete(context, request):
    tu = request.devpi_token_utility
    token_id = request.matchdict['id']
    tu.remove_token(context.user, token_id)
    apireturn(200, "token %s deleted" % token_id)


@view_config(
    route_name="user-tokens",
    request_method="GET",
    permission="user_modify")
def user_tokens_info(context, request):
    tu = request.devpi_token_utility
    result = dict(
        tokens=tu.get_tokens_info(context.user))
    apireturn(200, type="tokens-info", result=result)
