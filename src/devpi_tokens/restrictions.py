import pymacaroons
import time


available_restrictions = dict()


def restriction(name):
    def restriction(cls):
        if name in available_restrictions:
            raise ValueError("Restriction names '%s' already exists." % name)
        cls.name = name
        available_restrictions[name] = cls
        return cls
    return restriction


class Restriction:
    def __init__(self, value):
        raise NotImplementedError

    def __eq__(self, other):
        return self.value == other.value

    def dump(self):
        return "%s=%s" % (self.name, self.value)


@restriction("expires")
class ExpiresRestriction(Restriction):
    def __init__(self, value):
        if value != "never":
            try:
                value = int(value)
            except ValueError:
                raise ValueError("Invalid value '%s' for expiration" % value)
        self.value = value


class Restrictions:
    def __init__(self):
        self._restrictions = []

    def __getitem__(self, key):
        result = []
        for restriction in self._restrictions:
            if restriction.name != key:
                continue
            result.append(restriction)
        if not result:
            raise KeyError("No restriction named '%s'" % key)
        return result

    def __iter__(self):
        return iter(self._restrictions)

    def add(self, restriction):
        if restriction is None:
            return
        self._restrictions.append(restriction)

    @property
    def names(self):
        return [x.name for x in self._restrictions]


def get_request_value(request, key, default=None):
    if request.body:
        data = request.json_body
    else:
        data = {}
    if key in data:
        return data[key]
    return default


def extended_expiration_allowed(request):
    allowed = request.registry["xom"].config.restrict_modify
    if allowed is None:
        allowed = {'root'}
    return request.authenticated_userid in allowed


def get_expires_restriction_from_request(request):
    default_expires = time.time() + 31536000  # one year by default
    expires = get_request_value(
        request, ExpiresRestriction.name, default_expires)
    try:
        restriction = ExpiresRestriction(expires)
    except ValueError as e:
        request.apireturn(400, e.args[0])
    if restriction.value == "never":
        if not extended_expiration_allowed(request):
            request.apireturn(403, "Not allowed to create token with no expiration")
    else:
        if restriction.value <= time.time():
            request.apireturn(400, "Can't set expiration before current time")
        if restriction.value > default_expires and not extended_expiration_allowed(request):
            request.apireturn(403, "Not allowed to set expiration to more than one year")
    return restriction


def get_restrictions_from_request(request):
    restrictions = Restrictions()
    restrictions.add(
        get_expires_restriction_from_request(request))
    return restrictions


def get_restrictions_from_macaroon(macaroon):
    restrictions = Restrictions()
    for caveat in macaroon.caveats:
        (key, value) = caveat.to_dict()['cid'].split("=", 1)
        restriction_cls = available_restrictions[key]
        restrictions.add(restriction_cls(value))
    return restrictions


def get_restrictions_from_token(token):
    return get_restrictions_from_macaroon(
        pymacaroons.Macaroon.deserialize(token))
