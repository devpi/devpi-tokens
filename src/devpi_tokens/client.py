from delta import parse as parse_delta
from devpi_tokens.restrictions import ExpiresRestriction
from devpi_tokens.restrictions import IndexesRestriction
from devpi_tokens.restrictions import ProjectsRestriction
from devpi_tokens.restrictions import Restrictions
from getpass import getpass
from pluggy import HookimplMarker
import datetime
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


def add_restrictions_args(parser, expires_default):
    parser.add_argument(
        "-e", "--expires", action="store", default=expires_default,
        help="expiration as epoch timestamp or delta with units: y(ear(s)), "
             "m(onth(s)), w(eek(s)), d(ay(s)), h(our(s)), min(ute(s)) and "
             "s(econd(s))")
    parser.add_argument(
        "-i", "--indexes", action="append", default=None,
        help="comma separated list of indexes to limit the token to. "
             "Can also be used multiple times to extend the list.")
    parser.add_argument(
        "-p", "--projects", action="append", default=None,
        help="comma separated list of projects to limit the token to. "
             "Can also be used multiple times to extend the list.")


def add_user_arg(parser):
    parser.add_argument(
        "-u", "--user", action="store", default=None,
        help="user name to use instead of currently logged in")


def get_expires_from_args(hub, args):
    expires = args.expires
    if expires is not None and expires != "never":
        try:
            expires = int(
                (datetime.datetime.utcnow() + parse_delta(expires)).timestamp())
        except Exception:
            hub.fatal("Can't parse expiration '%s'" % expires)
    return expires


def get_indexes_from_args(hub, args):
    if args.indexes is None:
        return None
    indexes = []
    for item in args.indexes:
        for index in item.split(','):
            indexes.append(index.strip())
    return sorted(indexes)


def get_projects_from_args(hub, args):
    if args.projects is None:
        return None
    projects = []
    for item in args.projects:
        for index in item.split(','):
            projects.append(index.strip())
    return sorted(projects)


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


def get_user_from_args(hub, args):
    user = getattr(args, "user", None)
    if user is None:
        user = hub.current.get_auth_user()
    return user


def get_user_url_from_args(hub, args):
    user = get_user_from_args(hub, args)
    return hub.current.get_user_url(user).asdir()


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
    """ Create a token for user.
    """
    add_user_arg(parser)
    add_restrictions_args(parser, expires_default="1 year")


def token_create(hub, args):
    hub.requires_login()
    url = get_user_url_from_args(hub, args).joinpath('+token-create')
    expires = get_expires_from_args(hub, args)
    indexes = get_indexes_from_args(hub, args)
    projects = get_projects_from_args(hub, args)
    r = hub.http_api(
        "post", url,
        kvdict=dict(
            expires=expires,
            indexes=indexes,
            projects=projects),
        type="token-info")
    token = r.result["token"]
    hub.line(token)


def token_delete_arguments(parser):
    """ Delete a token for user. Any derived tokens will be invalidated as well.
    """
    add_user_arg(parser)
    parser.add_argument(
        "token_id", action="store",
        help="the id of the token to be deleted")


def token_delete(hub, args):
    hub.requires_login()
    url = get_user_url_from_args(hub, args).joinpath('+tokens', args.token_id)
    r = hub.http_api("delete", url)
    hub.line(r.json_get("message"))


def token_derive_arguments(parser):
    """ Derive a new token from an existing token with added restrictions.
        No connection to the server required.
        The new restrictions are validated one after another by the server
        when the token is used for authentication.
        It is not possible to remove existing restrictions,
        only adding additional ones.
    """
    add_token_args(parser)
    add_restrictions_args(parser, expires_default=None)


def token_derive(hub, args):
    restrictions = Restrictions()
    expires = get_expires_from_args(hub, args)
    if expires is not None:
        restrictions.add(ExpiresRestriction(expires))
    indexes = get_indexes_from_args(hub, args)
    if indexes is not None:
        restrictions.add(IndexesRestriction(indexes))
    projects = get_projects_from_args(hub, args)
    if projects is not None:
        restrictions.add(ProjectsRestriction(projects))
    if not restrictions:
        hub.fatal("No restrictions provided")
    token = get_token_from_args(hub, args)
    macaroon = get_token_macaroon(hub, token)
    for restriction in restrictions:
        macaroon.add_first_party_caveat(restriction.dump())
    hub.line(macaroon.serialize())


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
    for caveat in macaroon.caveats:
        info.append(('restriction', caveat.to_dict()['cid']))
    just_len = max(len(x[0]) for x in info)
    info_text = textwrap.indent(
        "\n".join("%s: %s" % (k.ljust(just_len), v) for k, v in info),
        "    ")
    hub.info("Token info:")
    hub.line(info_text)


def token_list_arguments(parser):
    """ List tokens for user.
    """
    add_user_arg(parser)


def token_list(hub, args):
    hub.requires_login()
    user = get_user_from_args(hub, args)
    url = get_user_url_from_args(hub, args).joinpath('+tokens')
    r = hub.http_api("get", url, type="tokens-info")
    tokens = sorted(r.result["tokens"].items())
    if not tokens:
        hub.info("No tokens for '%s'" % user)
        return
    hub.info("Tokens for '%s':" % user)
    for token_id, token_info in tokens:
        hub.info("    %s" % token_id)
        if "restrictions" in token_info:
            hub.line("        restrictions:")
            hub.line(textwrap.indent(
                "\n".join(token_info["restrictions"]),
                "            "))


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
        (token_derive_arguments, "token-derive", "devpi_tokens.client:token_derive"),
        (token_inspect_arguments, "token-inspect", "devpi_tokens.client:token_inspect"),
        (token_list_arguments, "token-list", "devpi_tokens.client:token_list"),
        (token_login_arguments, "token-login", "devpi_tokens.client:token_login")]
