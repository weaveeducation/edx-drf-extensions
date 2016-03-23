""" Authentication classes. """

import datetime
import logging

import requests
from dateutil.parser import parse
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header, BaseAuthentication
from rest_framework.status import HTTP_200_OK

logger = logging.getLogger(__name__)
User = get_user_model()


class BearerAuthentication(BaseAuthentication):
    """
    Simple token based authentication.

    This authentication class is useful for authenticating an OAuth2 access token
     against a remote authentication provider.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Bearer ".

    Examples:
        Authorization: Bearer 401f7ac837da42b97f613d789819ff93537bee6a
    """

    def get_access_token_url(self):
        """ Returns the URL, hosted by the OAuth2 provider, against which access tokens can be validated. """
        return getattr(settings, 'OAUTH2_ACCESS_TOKEN_URL', None)

    def authenticate(self, request):
        if not self.get_access_token_url():
            return None

        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'bearer':
            return None

        if len(auth) == 1:
            raise exceptions.AuthenticationFailed('Invalid token header. No credentials provided.')
        elif len(auth) > 2:
            raise exceptions.AuthenticationFailed('Invalid token header. Token string should not contain spaces.')

        return self.authenticate_credentials(auth[1].decode('utf8'))

    def authenticate_credentials(self, token):
        """
        Validate the bearer token against the OAuth provider.

        Arguments:
            token (str) -- Access token to validate

        Returns:
            User -- User associated with the access token
            str -- Access token

        Raises:
            AuthenticationFailed -- when user is inactive, or does not exist.
        """

        url = '{root}/{token}'.format(root=self.get_access_token_url().rstrip('/'), token=token)
        response = requests.get(url)

        if response.status_code != HTTP_200_OK:
            raise exceptions.AuthenticationFailed('Invalid token.')

        data = response.json()

        # Validate the expiration datetime
        expires = parse(data['expires'])

        if expires < datetime.datetime.utcnow():
            raise exceptions.AuthenticationFailed('Token expired.')

        try:
            user = User.objects.get(username=data['username'])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('The user linked to this token does not exist on this system.')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted.')

        return user, token

    def authenticate_header(self, request):
        return 'Bearer'
