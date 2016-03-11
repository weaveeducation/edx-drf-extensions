# -*- coding: utf-8 -*-
""" Tests for authentication classes. """

import json

import httpretty
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import override_settings, RequestFactory, TestCase
from rest_framework.exceptions import AuthenticationFailed

from edx_rest_framework_extensions.authentication import BearerAuthentication
from edx_rest_framework_extensions.tests import factories

OAUTH2_ACCESS_TOKEN_URL = 'http://example.com/oauth2/access_token/'

User = get_user_model()


class AccessTokenMixin(object):
    """ Test mixin for dealing with OAuth2 access tokens. """
    DEFAULT_TOKEN = 'abc123'

    def mock_access_token_response(self, status=200, token=DEFAULT_TOKEN, username='fake-user'):
        """ Mock the access token endpoint response of the OAuth2 provider. """
        url = '{root}/{token}'.format(root=OAUTH2_ACCESS_TOKEN_URL.rstrip('/'), token=token)
        httpretty.register_uri(
            httpretty.GET,
            url,
            body=json.dumps({'username': username, 'scope': 'read', 'expires_in': 60}),
            content_type="application/json",
            status=status
        )


@override_settings(OAUTH2_ACCESS_TOKEN_URL=OAUTH2_ACCESS_TOKEN_URL)
class BearerAuthenticationTests(AccessTokenMixin, TestCase):
    """ Tests for the BearerAuthentication class. """

    def setUp(self):
        super(BearerAuthenticationTests, self).setUp()
        self.auth = BearerAuthentication()
        self.factory = RequestFactory()

    def create_authenticated_request(self, token=AccessTokenMixin.DEFAULT_TOKEN, token_name='Bearer'):
        """ Returns a Request with the authorization set using the specified values. """
        auth_header = '{token_name} {token}'.format(token_name=token_name, token=token)
        request = self.factory.get('/', HTTP_AUTHORIZATION=auth_header)
        return request

    def assert_user_authenticated(self):
        """ Assert a user can be authenticated with a bearer token. """
        user = factories.UserFactory()
        self.mock_access_token_response(username=user.username)

        request = self.create_authenticated_request()
        self.assertEqual(self.auth.authenticate(request), (user, self.DEFAULT_TOKEN))

    def test_authenticate_header(self):
        """ The method should return the string Bearer. """
        self.assertEqual(self.auth.authenticate_header(self.create_authenticated_request()), 'Bearer')

    @override_settings(OAUTH2_ACCESS_TOKEN_URL=None)
    def test_authenticate_no_access_token_url(self):
        """ If the setting OAUTH2_ACCESS_TOKEN_URL is not set, the method returns None. """

        # Empty value
        self.assertIsNone(self.auth.authenticate(self.create_authenticated_request()))

        # Missing value
        del settings.OAUTH2_PROVIDER_URL
        self.assertIsNone(self.auth.authenticate(self.create_authenticated_request()))

    def test_authenticate_invalid_token(self):
        """ If no token is supplied, or if the token contains spaces, the method should raise an exception. """

        # Missing token
        request = self.create_authenticated_request('')
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

        # Token with spaces
        request = self.create_authenticated_request('abc 123 456')
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    def test_authenticate_invalid_token_name(self):
        """ If the token name is not Bearer, the method should return None. """
        request = self.create_authenticated_request(token_name='foobar')
        self.assertIsNone(self.auth.authenticate(request))

    @httpretty.activate
    def test_authenticate_missing_user(self):
        """ If the user matching the access token does not exist, the method should raise an exception. """
        self.mock_access_token_response()
        request = self.create_authenticated_request()

        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    @httpretty.activate
    def test_authenticate_inactive_user(self):
        """ If the user matching the access token is inactive, the method should raise an exception. """
        user = factories.UserFactory(is_active=False)

        self.mock_access_token_response(username=user.username)

        request = self.create_authenticated_request()
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    @httpretty.activate
    def test_authenticate_invalid_token_response(self):
        """ If the OAuth2 provider does not return HTTP 200, the method should return raise an exception. """
        self.mock_access_token_response(status=400)
        request = self.create_authenticated_request()
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    @httpretty.activate
    def test_authenticate(self):
        """ If the access token is valid, the user exists, and is active, a tuple containing
        the user and token should be returned.
        """
        self.assert_user_authenticated()

    @httpretty.activate
    @override_settings(OAUTH2_ACCESS_TOKEN_URL=OAUTH2_ACCESS_TOKEN_URL[:-1])
    def test_authenticate_without_trailing_slash(self):
        """ Verify access tokens are validated when the OAUTH2_ACCESS_TOKEN_URL setting value
        does not end with a trailing slash.
        """
        self.assert_user_authenticated()
