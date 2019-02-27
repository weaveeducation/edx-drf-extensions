"""
Middleware to ensure best practices of DRF and other endpoints.
"""
from edx_django_utils import monitoring

from django.conf import settings
from django.contrib.auth.models import Group
from django.core.cache import cache

from edx_rest_framework_extensions.auth.jwt.cookies import (
    jwt_cookie_name,
)
from edx_rest_framework_extensions.auth.jwt.decoder import jwt_decode_handler
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication


class RequestMetricsMiddleware(object):
    """
    Adds various request related metrics.

    Possible metrics include:
        request_auth_type: Example values include: no-user, unauthenticated,
            jwt, bearer, other-token-type, or session-or-unknown
        request_client_name: The client name from edx-rest-api-client calls.
        request_referer
        request_user_agent: The user agent string from the request header.
        request_user_id: The user id of the request user.

    This middleware is dependent on the RequestCacheMiddleware. You must
    include this middleware later.  For example::

        MIDDLEWARE_CLASSES = (
            'edx_django_utils.cache.middleware.RequestCacheMiddleware',
            'edx_rest_framework_extensions.middleware.RequestMetricsMiddleware',
        )

    This middleware should also appear after any authentication middleware.

    """

    def process_response(self, request, response):
        """
        Add metrics for various details of the request.
        """
        self._set_request_auth_type_metric(request)
        self._set_request_user_agent_metrics(request)
        self._set_request_referer_metric(request)
        self._set_request_user_id_metric(request)

        return response

    def _set_request_user_id_metric(self, request):
        """
        Add request_user_id metric

        Metrics:
             request_user_id
        """
        if hasattr(request, 'user') and hasattr(request.user, 'id') and request.user.id:
            monitoring.set_custom_metric('request_user_id', request.user.id)

    def _set_request_referer_metric(self, request):
        """
        Add metric 'request_referer' for http referer.
        """
        if 'HTTP_REFERER' in request.META and request.META['HTTP_REFERER']:
            monitoring.set_custom_metric('request_referer', request.META['HTTP_REFERER'])

    def _set_request_user_agent_metrics(self, request):
        """
        Add metrics for user agent for python.

        Metrics:
             request_user_agent
             request_client_name: The client name from edx-rest-api-client calls.
        """
        if 'HTTP_USER_AGENT' in request.META and request.META['HTTP_USER_AGENT']:
            user_agent = request.META['HTTP_USER_AGENT']
            monitoring.set_custom_metric('request_user_agent', user_agent)
            if user_agent:
                # Example agent string from edx-rest-api-client:
                #    python-requests/2.9.1 edx-rest-api-client/1.7.2 ecommerce
                #    See https://github.com/edx/edx-rest-api-client/commit/692903c30b157f7a4edabc2f53aae1742db3a019
                user_agent_parts = user_agent.split()
                if len(user_agent_parts) == 3 and user_agent_parts[1].startswith('edx-rest-api-client/'):
                    monitoring.set_custom_metric('request_client_name', user_agent_parts[2])

    def _set_request_auth_type_metric(self, request):
        """
        Add metric 'request_auth_type' for the authentication type used.

        NOTE: This is a best guess at this point.  Possible values include:
            no-user
            unauthenticated
            jwt/bearer/other-token-type
            session-or-unknown (catch all)

        """
        if 'HTTP_AUTHORIZATION' in request.META and request.META['HTTP_AUTHORIZATION']:
            token_parts = request.META['HTTP_AUTHORIZATION'].split()
            # Example: "JWT eyJhbGciO..."
            if len(token_parts) == 2:
                auth_type = token_parts[0].lower()  # 'jwt' or 'bearer' (for example)
            else:
                auth_type = 'other-token-type'
        elif not hasattr(request, 'user') or not request.user:
            auth_type = 'no-user'
        elif not request.user.is_authenticated:
            auth_type = 'unauthenticated'
        else:
            auth_type = 'session-or-unknown'
        monitoring.set_custom_metric('request_auth_type', auth_type)

class JwtAuthCookieRoleMiddleware(object):
    """
    """
    @staticmethod
    def add_user_role(role, user):
        mapped_role = settings.ROLE_MAPPING.get(role)
        if mapped_role and not user.groups.filter(name=mapped_role).exists():
            group, _ = Group.objects.get_or_create(name=mapped_role)
            group.user_set.add(user)

    @staticmethod
    def remove_user_role(role, user):
        mapped_role = settings.ROLE_MAPPING.get(role)
        if mapped_role and user.groups.filter(name=mapped_role).exists():
            group, _ = Group.objects.get_or_create(name=mapped_role)
            group.user_set.remove(user)

    def process_request(self, request):
        """
        """
        user = request.user
        jwt_cookie = request.COOKIES.get(jwt_cookie_name(), None)
        if not jwt_cookie:
            return

        decoded_jwt = jwt_decode_handler(jwt_cookie)
        if not request.user.is_authenticated:
            user = JwtAuthentication().authenticate_credentials(decoded_jwt)

        roles_claim = decoded_jwt.get('roles')
        role_cache_key = '{user_id}:role_metadata'.format(user_id=user.id)
        previous_role_cache_data = cache.get(role_cache_key) or {}

        if not roles_claim:
            for role in previous_role_cache_data.keys():
                self.remove_user_role(role, user)
            cache.delete(role_cache_key)
            return

        role_cache_data = {}
        for role_data in roles_claim:
            role, object_type, object_key = role_data.split(':')
            self.add_user_role(role, user)

            if role not in role_cache_data:
                role_cache_data[role] = []

            role_cache_data[role].append(object_key)

        for role in previous_role_cache_data.keys():
            if role not in role_cache_data:
                self.remove_user_role(role, user)

        cache.set(role_cache_key, role_cache_data)
