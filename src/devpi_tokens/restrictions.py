from functools import total_ordering
import pymacaroons
import time


ONE_YEAR_SECONDS = 366 * 24 * 60 * 60 + 10  # seconds of a leap year + 10 seconds to spare
available_restrictions = dict()


def restriction(name):
    def restriction(cls):
        if name in available_restrictions:
            raise ValueError("Restriction names '%s' already exists." % name)
        cls.name = name
        available_restrictions[name] = cls
        return cls
    return restriction


@total_ordering
class Restriction:
    def __init__(self, value):
        raise NotImplementedError

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.value == other.value

    def __lt__(self, other):
        return self.value < other.value

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.value)

    def dump(self):
        return "%s=%s" % (self.name, self.value)

    def validate_against_request(self, request):  # noqa: ARG002
        return


@restriction("expires")
class ExpiresRestriction(Restriction):
    def __init__(self, value):
        self.default_expires = time.time() + ONE_YEAR_SECONDS
        if value is None:
            value = self.default_expires
        if value != "never":
            try:
                value = int(value)
            except ValueError as e:
                raise ValueError("Invalid value '%s' for expiration" % value) from e
        self.value = value

    def validate_against_request(self, request):
        if self.value == "never":
            if not extended_expiration_allowed(request):
                request.apireturn(403, "Not allowed to create token with no expiration")
        else:
            if self.value <= time.time():
                request.apireturn(400, "Can't set expiration before current time")
            if self.value > self.default_expires and not extended_expiration_allowed(request):
                request.apireturn(403, "Not allowed to set expiration to more than one year")


@restriction("not_before")
class NotBeforeRestriction(Restriction):
    def __init__(self, value):
        try:
            value = int(value)
        except ValueError as e:
            raise ValueError(f"Invalid value '{value}' for not before") from e
        self.value = value

    def validate_against_request(self, request):  # noqa: ARG002
        return


class ListRestriction(Restriction):
    def validate_item(self, index, item):  # noqa: ARG002
        return

    def __init__(self, value):
        if not isinstance(value, list):
            raise ValueError("The %s restriction must be a list" % self.name)
        for index, item in enumerate(value, 1):
            self.validate_item(index, item)
        self.value = value

    def dump(self):
        return "%s=%s" % (self.name, ",".join(self.value))


class StringListRestriction(ListRestriction):
    def __init__(self, value):
        super().__init__(value)
        self.value = sorted(self.value)

    def validate_item(self, index, item):
        super().validate_item(index, item)
        if not isinstance(item, str):
            raise ValueError("Item at position %s is not a string in %s list" % (
                index, self.name))
        if not item:
            raise ValueError("Empty item at position %s in %s list" % (
                index, self.name))


@restriction("allowed")
class AllowedRestriction(StringListRestriction):
    pass


@restriction("indexes")
class IndexesRestriction(StringListRestriction):
    pass


@restriction("projects")
class ProjectsRestriction(StringListRestriction):
    pass


class Restrictions:
    def __init__(self):
        self._restrictions = []

    def __bool__(self):
        return bool(self._restrictions)

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

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    @property
    def names(self):
        return [x.name for x in self._restrictions]

    def __repr__(self):
        return "[%s]" % ", ".join(repr(x) for x in self)


def extended_expiration_allowed(request):
    allowed = request.registry["xom"].config.restrict_modify
    if allowed is None:
        allowed = {'root'}
    return request.authenticated_userid in allowed


def get_restrictions_from_request(request):
    restrictions = Restrictions()
    if request.body:
        data = dict(request.json_body)
    else:
        data = {}
    data.setdefault("expires", None)
    for key, value in sorted(data.items()):
        if key not in available_restrictions:
            request.apireturn(400, "Unknown restriction '%s'." % key)
        restriction_cls = available_restrictions[key]
        try:
            restriction = restriction_cls(value)
        except ValueError as e:
            request.apireturn(400, e.args[0])
        restriction.validate_against_request(request)
        restrictions.add(restriction)
    return restrictions


def get_restrictions_from_macaroon(macaroon):
    restrictions = Restrictions()
    for caveat in macaroon.caveats:
        (key, value) = caveat.to_dict()['cid'].split("=", 1)
        restriction_cls = available_restrictions[key]
        if issubclass(restriction_cls, ListRestriction):
            value = value.split(',')
        restrictions.add(restriction_cls(value))
    return restrictions


def get_restrictions_from_token(token):
    if token.startswith('devpi-'):
        token = token[6:]
    return get_restrictions_from_macaroon(
        pymacaroons.Macaroon.deserialize(token))
