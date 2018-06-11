""" Internal decorator functions for scope-enforcing permission classes. """
from functools import wraps

import waffle
from edx_rest_framework_extensions.authentication import JwtAuthentication
from edx_rest_framework_extensions.config import SWITCH_ENFORCE_JWT_SCOPES


def skip_unless_jwt_authenticated(f):
    """
    Permission class decorator for ensuring that authentication
    was performed using JwtAuthentication before performing the
    permission check.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """ Determine if JwtAuthentication was used to authenticate the request. """
        request = args[1]
        if isinstance(request.successful_authenticator, JwtAuthentication):
            if getattr(request, 'auth', None):
                return f(*args, **kwargs)
            else:
                # Something went wrong with JwtAuthentication and
                # the auth attribute did not get populated with the
                # JWT on the request object.
                return False
        # We will skip scope enforcement if JwtAuthentication
        # was not used to authenticate the request.
        return True
    return decorated_function


def skip_unless_jwt_scopes_enforced(f):
    """
    Permission class decorator for ensuring that scope enforcement
    is enabled before performing the permission check.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """ Determine if scope enforcement is enabled. """
        if waffle.switch_is_active(SWITCH_ENFORCE_JWT_SCOPES):
            return f(*args, **kwargs)
        return True
    return decorated_function
