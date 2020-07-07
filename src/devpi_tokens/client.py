from pluggy import HookimplMarker


client_hookimpl = HookimplMarker("devpiclient")


def create_token_arguments(parser):
    """ Create a token for current user.
    """


def create_token(hub, args):
    hub.requires_login()
    url = hub.current.get_user_url().asdir().joinpath('+token-create')
    r = hub.http_api("post", url, type="token-info")
    token = r.result["token"]
    hub.line(token)


@client_hookimpl
def devpiclient_subcommands():
    return [
        (create_token_arguments, "create-token", "devpi_tokens.client:create_token")]
