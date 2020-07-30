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


def create_token_arguments(parser):
    """ Create a token for current user.
    """


def create_token(hub, args):
    hub.requires_login()
    url = hub.current.get_user_url().asdir().joinpath('+token-create')
    r = hub.http_api("post", url, type="token-info")
    token = r.result["token"]
    hub.line(token)


def inspect_token_arguments(parser):
    """ Inspect a given token.
    """
    add_token_args(parser)


def inspect_token(hub, args):
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


def token_login_arguments(parser):
    """ Login using a token.
    """
    add_token_args(parser)


def token_login(hub, args):
    token = get_token_from_args(hub, args)
    macaroon = get_token_macaroon(hub, token)
    (token_user, token_id) = get_macaroon_user_id(hub, macaroon)
    hub.current.set_auth(token_user, token)
    msg = "logged in %r" % token_user
    if hub.current.index:
        msg = "%s at %r" % (msg, hub.current.index)
    hub.info(msg)


@client_hookimpl
def devpiclient_subcommands():
    return [
        (create_token_arguments, "create-token", "devpi_tokens.client:create_token"),
        (inspect_token_arguments, "inspect-token", "devpi_tokens.client:inspect_token"),
        (token_login_arguments, "token-login", "devpi_tokens.client:token_login")]
