"""
Deprecated imports for authentication classes that moved.

TODO: ARCH-244: Remove this file of backward compatible imports.
WARNING: Do NOT add new code to this file. If needed add in edx_rest_framework_extensions/auth.
"""
from edx_rest_framework_extensions.auth.jwt.authentication import (
    JwtAuthentication,
    is_jwt_authenticated,
)  # pylint: disable=unused-import
from edx_rest_framework_extensions.auth.bearer.authentication import (
    BearerAuthentication,
)  # pylint: disable=unused-import
from edx_rest_framework_extensions.auth.session.authentication import (
    SessionAuthenticationAllowInactiveUser
)  # pylint: disable=unused-import
from edx_rest_framework_extensions.auth.oauth2.authentication import (
    OAuth2AuthenticationAllowInactiveUser
)  # pylint: disable=unused-import
