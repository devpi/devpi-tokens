from devpi_server.views import apireturn
from pyramid.view import view_config


@view_config(
    route_name="user-token-create",
    request_method="POST",
    permission="user_modify")
def user_token_create(context, request):
    tu = request.devpi_token_utility
    result = dict(
        token=tu.new_token(context.user))
    apireturn(200, type="token-info", result=result)
