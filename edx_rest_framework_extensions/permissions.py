""" Permission classes. """
from rest_framework.permissions import BasePermission

from edx_rest_framework_extensions.authentication import JwtAuthentication


class IsSuperuser(BasePermission):
    """ Allows access only to superusers. """

    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class JwtScopePermissions(BasePermission):
    """
    JWT-based scope permissions handler.

    This permissions class should be used in conjunction with
    :any:`JwtAuthentication`. This class compares the scopes listed in the
    JWT's `scopes` claim with the scopes required by the available HTTP options.

    Scopes should adhere to the format specified by
    `OEP-4 <http://open-edx-proposals.readthedocs.io/en/latest/oep-0004.html>`_: ``resource:action``.

    Consuming views should specify a ``scope_resource`` class variable. This variable will be used to build the list of
    required scopes for each HTTP verb.

    Consuming views can also provide a dictionary mapping HTTP verbs to scope actions. By default, `GET`, `OPTIONS`,
    and `HEAD` are mapped to the `read` scope action. `DELETE`, `PATCH`, `POST`, and `PUT` are mapped to the `write`
    scope action. These can be overwritten by defining a ``scope_action_map`` class variable on the view.

    Additionally, users with JWT scopes containing the ``<resource>:all`` scope (e.g. ``catalog:all``) will be
    permitted to perform any action. This is equivalent to being a superuser.

    Note:
        If the request is not authenticated by :any:`JwtAuthentication`, scope permissions will be ignored.
        ``has_permission()`` will simply return `True`. This allows for other authentication/authorization schemes to
        be used—specifically ``SessionAuthentication``.
    """
    ALL_ACTION = 'all'

    ACTION_MAP = {
        'GET': 'read',
        'OPTIONS': 'read',
        'HEAD': 'read',
        'POST': 'write',
        'PUT': 'write',
        'PATCH': 'write',
        'DELETE': 'write',
    }

    def get_action_map(self, view):
        return getattr(view, 'scope_action_map', self.ACTION_MAP)

    def get_resource(self, view):
        resource = getattr(view, 'scope_resource', None)

        if not resource:
            serializer_class = view.get_serializer_class()
            resource = serializer_class.Meta.model.__name__.lower()

        return resource

    def has_permission(self, request, view):
        # NOTE: These permissions only apply when using JWT authentication. This allows us to
        # support both JWT and session authentication.
        if not isinstance(request.successful_authenticator, JwtAuthentication):
            return True

        token = request.auth
        if not token:
            return False

        token_scopes = set(token.get('scopes', []))
        if not token_scopes:
            return False

        required_scopes = set(self.get_required_scopes(request, view))
        return bool(required_scopes.intersection(token_scopes))

    def get_required_scopes(self, request, view):
        resource = self.get_resource(view)
        actions = [self.ALL_ACTION, self.get_action_map(view)[request.method]]
        return ['{resource}:{action}'.format(resource=resource, action=action) for action in actions]

# TEST CODE
# from time import time
#
# import jwt
# from edx_rest_api_client.client import EdxRestApiClient
#
# now = int(time())
# expires_in = 3600
# secret = 'lms-secret'
#
# payload = {
#     'aud': 'lms-key',
#     'exp': now + expires_in,
#     'iat': now,
#     'iss': 'http://127.0.0.1:8000/oauth2',
#     'preferred_username': 'edx',
#     'scopes': ['catalog:read', 'catalog:write'],
#     'sub': '1234',
# }
#
# token = jwt.encode(payload, secret).decode('utf-8')
# print(token)
#
# client = EdxRestApiClient('http://cd.local:8008/api/v1/', jwt=token)
# print(client.catalogs.get())
# print(client.catalogs.post({}))
