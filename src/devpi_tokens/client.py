from getpass import getpass
from pluggy import HookimplMarker
import py
import pymacaroons
import sys
import traceback


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


def token_login_arguments(parser):
    """ Login using a token.
    """
    parser.add_argument(
        "-f", "--file", action="store", default=None,
        help="file containing the token, use - to read from standard input")
    parser.add_argument(
        "--token", action="store", default=None,
        help="the token as a parameter, not recommended as it can easily "
             "appear in log files etc")


def token_login(hub, args):
    if args.file:
        if args.file == "-":
            token = sys.stdin.readline().strip()
        else:
            path = py.path.local(args.file)
            if not path.exists():
                hub.fatal("The file for the token doesn't exist.")
            with path.open(encoding="ascii") as f:
                token = f.readline().strip()
    elif args.token:
        token = args.token
    else:
        token = getpass("token: ")
    try:
        macaroon = pymacaroons.Macaroon.deserialize(token)
        (token_user, token_id) = macaroon.identifier.decode("ascii").rsplit('-', 1)
    except Exception as e:
        hub.fatal("Invalid token: %s" % "".join(traceback.format_exception_only(e.__class__, e)))
    hub.current.set_auth(token_user, token)
    msg = "logged in %r" % token_user
    if hub.current.index:
        msg = "%s at %r" % (msg, hub.current.index)
    hub.info(msg)


@client_hookimpl
def devpiclient_subcommands():
    return [
        (create_token_arguments, "create-token", "devpi_tokens.client:create_token"),
        (token_login_arguments, "token-login", "devpi_tokens.client:token_login")]
