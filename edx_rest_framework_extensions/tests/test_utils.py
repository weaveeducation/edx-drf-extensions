""" Tests for utility functions. """
from time import time

import jwt
import mock
from django.conf import settings
from django.test import TestCase

from edx_rest_framework_extensions.tests.factories import UserFactory
from edx_rest_framework_extensions.utils import jwt_decode_handler


def generate_jwt_token(payload):
    """Generate a valid JWT token for authenticated requests."""
    return jwt.encode(payload, settings.JWT_AUTH['JWT_SECRET_KEY']).decode('utf-8')


def generate_jwt_payload(user):
    """Generate a valid JWT payload given a user."""
    now = int(time())
    ttl = 5
    return {
        'iss': settings.JWT_AUTH['JWT_ISSUER'],
        'aud': settings.JWT_AUTH['JWT_AUDIENCE'],
        'username': user.username,
        'email': user.email,
        'iat': now,
        'exp': now + ttl
    }


class JWTDecodeHandlerTests(TestCase):
    """ Tests for the `jwt_decode_handler` utility function. """
    def setUp(self):
        super(JWTDecodeHandlerTests, self).setUp()
        self.user = UserFactory()
        self.payload = generate_jwt_payload(self.user)
        self.jwt = generate_jwt_token(self.payload)

    def test_decode_success(self):
        self.assertDictEqual(jwt_decode_handler(self.jwt), self.payload)

    def test_decode_error(self):
        with mock.patch('edx_rest_framework_extensions.utils.logger') as patched_log:
            with self.assertRaises(jwt.InvalidTokenError):
                jwt_decode_handler('not.a.valid.jwt')
            patched_log.exception.assert_called_once_with('JWT decode failed!')
