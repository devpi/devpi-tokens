from getpass import getpass
from pluggy import HookimplMarker
import py
import pymacaroons
import sys
import textwrap
import traceback


client_hookimpl = HookimplMarker("devpiclient")


def add_token_args(parser):
    parser.add_argument(
        "-f", "--file", action="store", default=None,
        help="file containing the token, use - to read from standard input")
    parser.add_argument(
        "--token", action="store", default=None,
        help="the token as a parameter, not recommended as it can easily "
             "appear in log files etc")


def get_token_from_args(hub, args, use_getpass=True):
    if args.file:
        if args.file == "-":
            return sys.stdin.readline().strip()
        else:
            path = py.path.local(args.file)
            if not path.exists():
                hub.fatal("The file for the token doesn't exist.")
            with path.open(encoding="ascii") as f:
                return f.readline().strip()
    elif args.token:
        return args.token
    elif use_getpass:
        return getpass("token: ")


def get_token_macaroon(hub, token):
    try:
        return pymacaroons.Macaroon.deserialize(token)
    except Exception as e:
        hub.fatal("Invalid token: %s" % "".join(traceback.format_exception_only(e.__class__, e)))


def get_macaroon_user_id(hub, macaroon):
    try:
        return macaroon.identifier.decode("ascii").rsplit('-', 1)
    except Exception as e:
        hub.fatal("Invalid token: %s" % "".join(traceback.format_exception_only(e.__class__, e)))


def token_create_arguments(parser):
    """ Create a token for current user.
    """


def token_create(hub, args):
    hub.requires_login()
    url = hub.current.get_user_url().asdir().joinpath('+token-create')
    r = hub.http_api("post", url, type="token-info")
    token = r.result["token"]
    hub.line(token)


def token_delete_arguments(parser):
    """ Delete a token for current user.
    """
    parser.add_argument(
        "token_id", action="store",
        help="the id of the token to be deleted")


def token_delete(hub, args):
    hub.requires_login()
    url = hub.current.get_user_url().asdir().joinpath('+tokens', args.token_id)
    r = hub.http_api("delete", url)
    hub.line(r.json_get("message"))


def token_inspect_arguments(parser):
    """ Inspect a given token.
    """
    add_token_args(parser)


def token_inspect(hub, args):
    token = get_token_from_args(hub, args)
    macaroon = get_token_macaroon(hub, token)
    (token_user, token_id) = get_macaroon_user_id(hub, macaroon)
    info = [
        ('user', token_user),
        ('id', token_id)]
    info_text = textwrap.indent(
        "\n".join("%s: %s" % (k.ljust(8), v) for k, v in info),
        "    ")
    hub.info("Token info:")
    hub.line(info_text)


def token_list_arguments(parser):
    """ List tokens for current user.
    """


def token_list(hub, args):
    hub.requires_login()
    user = hub.current.get_auth_user()
    url = hub.current.get_user_url().asdir().joinpath('+tokens')
    r = hub.http_api("get", url, type="tokens-info")
    tokens = sorted(r.result["tokens"].items())
    if not tokens:
        hub.info("No tokens for '%s'" % user)
        return
    hub.info("Tokens for '%s':" % user)
    for token_id, token_info in tokens:
        hub.info("    %s" % token_id)


def token_login_arguments(parser):
    """ Login using a token.
    """
    add_token_args(parser)


def token_login(hub, args):
    token = get_token_from_args(hub, args)
    macaroon = get_token_macaroon(hub, token)
    (token_user, token_id) = get_macaroon_user_id(hub, macaroon)
    hub.current.set_auth(token_user, token)
    r = hub.http_api("get", hub.current.root_url.joinpath("+api"))
    authstatus = r.result.get("authstatus")
    if authstatus and authstatus[0] != "ok":
        hub.current.del_auth()
        hub.fatal("Login with token at %r failed" % hub.current.index)
    msg = "logged in %r" % token_user
    if hub.current.index:
        msg = "%s at %r" % (msg, hub.current.index)
    hub.info(msg)


@client_hookimpl
def devpiclient_subcommands():
    return [
        (token_create_arguments, "token-create", "devpi_tokens.client:token_create"),
        (token_delete_arguments, "token-delete", "devpi_tokens.client:token_delete"),
        (token_inspect_arguments, "token-inspect", "devpi_tokens.client:token_inspect"),
        (token_list_arguments, "token-list", "devpi_tokens.client:token_list"),
        (token_login_arguments, "token-login", "devpi_tokens.client:token_login")]
