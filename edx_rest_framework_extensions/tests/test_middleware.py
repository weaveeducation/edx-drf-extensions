"""
Unit tests for middlewares.
"""
import ddt
from django.contrib.auth.models import AnonymousUser, Group
from django.core.cache import cache
from django.test import override_settings, TestCase, RequestFactory
import jwt
from mock import call, patch

from edx_rest_framework_extensions.auth.jwt.cookies import (
    jwt_cookie_name,
)
from edx_rest_framework_extensions.auth.jwt.tests.utils import (
    generate_jwt_token,
    generate_unversioned_payload,
)
from edx_rest_framework_extensions.tests.factories import UserFactory
from edx_rest_framework_extensions.middleware import (
    JwtAuthCookieRoleMiddleware,
    RequestMetricsMiddleware,
)


@ddt.ddt
class TestRequestMetricsMiddleware(TestCase):
    def setUp(self):
        super(TestRequestMetricsMiddleware, self).setUp()
        self.request = RequestFactory().get('/')
        self.middleware = RequestMetricsMiddleware()

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_no_headers(self, mock_set_custom_metric):
        self.request.user = None
        self.middleware.process_response(self.request, None)
        mock_set_custom_metric.assert_called_once_with('request_auth_type', 'no-user')

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_blank_headers(self, mock_set_custom_metric):
        self.request.META['HTTP_USER_AGENT'] = ''
        self.request.META['HTTP_REFERER'] = ''
        self.request.META['HTTP_AUTHORIZATION'] = ''

        self.middleware.process_response(self.request, None)
        mock_set_custom_metric.assert_called_once_with('request_auth_type', 'no-user')

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_referer_metric(self, mock_set_custom_metric):
        self.request.META['HTTP_REFERER'] = 'test-http-referer'

        self.middleware.process_response(self.request, None)
        expected_calls = [
            call('request_referer', 'test-http-referer'),
            call('request_auth_type', 'no-user'),
        ]
        mock_set_custom_metric.assert_has_calls(expected_calls, any_order=True)

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_rest_client_user_agent_metrics(self, mock_set_custom_metric):
        self.request.META['HTTP_USER_AGENT'] = 'python-requests/2.9.1 edx-rest-api-client/1.7.2 test-client'

        self.middleware.process_response(self.request, None)
        expected_calls = [
            call('request_user_agent', 'python-requests/2.9.1 edx-rest-api-client/1.7.2 test-client'),
            call('request_client_name', 'test-client'),
            call('request_auth_type', 'no-user'),
        ]
        mock_set_custom_metric.assert_has_calls(expected_calls, any_order=True)

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_standard_user_agent_metrics(self, mock_set_custom_metric):
        self.request.META['HTTP_USER_AGENT'] = 'test-user-agent'

        self.middleware.process_response(self.request, None)
        expected_calls = [
            call('request_user_agent', 'test-user-agent'),
            call('request_auth_type', 'no-user'),
        ]
        mock_set_custom_metric.assert_has_calls(expected_calls, any_order=True)

    @ddt.data(
        ('jwt abcdefg', 'jwt'),
        ('bearer abcdefg', 'bearer'),
        ('abcdefg', 'other-token-type'),
    )
    @ddt.unpack
    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_auth_type_token_metric(self, token, expected_token_type, mock_set_custom_metric):
        self.request.META['HTTP_AUTHORIZATION'] = token

        self.middleware.process_response(self.request, None)
        mock_set_custom_metric.assert_called_once_with('request_auth_type', expected_token_type)

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_auth_type_anonymous_metric(self, mock_set_custom_metric):
        self.request.user = AnonymousUser()

        self.middleware.process_response(self.request, None)
        mock_set_custom_metric.assert_called_once_with('request_auth_type', 'unauthenticated')

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_auth_type_session_metric(self, mock_set_custom_metric):
        self.request.user = UserFactory()

        self.middleware.process_response(self.request, None)
        mock_set_custom_metric.assert_any_call('request_auth_type', 'session-or-unknown')

    @patch('edx_django_utils.monitoring.set_custom_metric')
    def test_request_user_id_metric(self, mock_set_custom_metric):
        self.request.user = UserFactory()

        self.middleware.process_response(self.request, None)
        mock_set_custom_metric.assert_any_call('request_user_id', self.request.user.id)


class TestJwtAuthCookieRoleMiddleware(TestCase):

    TEST_ROLE_MAPPING = {
        'enterprise_learner': 'enterprise_learner',
        'enterprise_admin': 'enterprise_admin',
    }

    def setUp(self):
        super(TestJwtAuthCookieRoleMiddleware, self).setUp()
        cache.clear()
        self.request = RequestFactory().get('/')
        self.request.user = UserFactory()
        self.middleware = JwtAuthCookieRoleMiddleware()

    def tearDown(self):
        super(TestJwtAuthCookieRoleMiddleware, self).tearDown()
        cache.clear()

    def test_request_no_jwt_cookie(self):
        """
        If there is no jwt cookiem then the process request should return
        without making any update to the cache. For the sake of a test, assert
        a key that should exist, had the jwt existed, does not.
        """
        self.middleware.process_request(self.request)
        cache_key = '{user_id}:role_metadata'.format(user_id=self.request.user.id)
        assert cache_key not in cache

    @patch('edx_rest_framework_extensions.middleware.JwtAuthCookieRoleMiddleware.remove_user_role')
    def test_no_roles_found_in_jwt_previous_role_exists(self, mock_remove_role):
        """
        """
        cache_key = '{user_id}:role_metadata'.format(user_id=self.request.user.id)
        roles = {
            'some_old_role_name': ['some_old_resource_id'],
        }
        cache.add(cache_key, roles)

        payload = generate_unversioned_payload(self.request.user)
        jwt_token = generate_jwt_token(payload)

        self.request.COOKIES[jwt_cookie_name()] = jwt_token
        self.middleware.process_request(self.request)

        assert cache_key not in cache
        assert mock_remove_role.call_count == 1

    @patch('edx_rest_framework_extensions.middleware.JwtAuthCookieRoleMiddleware.remove_user_role')
    def test_no_roles_found_in_jwt_previous_role_does_not_exist(self, mock_remove_role):
        """
        """
        cache_key = '{user_id}:role_metadata'.format(user_id=self.request.user.id)

        payload = generate_unversioned_payload(self.request.user)
        jwt_token = generate_jwt_token(payload)

        self.request.COOKIES[jwt_cookie_name()] = jwt_token
        self.middleware.process_request(self.request)

        assert cache_key not in cache
        assert mock_remove_role.call_count == 0

    @patch('edx_rest_framework_extensions.middleware.JwtAuthCookieRoleMiddleware.remove_user_role')
    @patch('edx_rest_framework_extensions.middleware.JwtAuthCookieRoleMiddleware.add_user_role')
    def test_roles_found_in_jwt_and_previous_role_exists(self, mock_add_role, mock_remove_role):
        """
        """
        cache_key = '{user_id}:role_metadata'.format(user_id=self.request.user.id)
        roles = {
            'some_old_role_name': ['some_old_resource_id'],
            'some_old_role_name2': ['some_old_resource_id2'],
        }
        cache.add(cache_key, roles)

        payload = generate_unversioned_payload(self.request.user)
        payload.update({
          "roles": [
            "some_new_role_name:some_new_resource_type:some_new_resource_id"
          ]
        })
        jwt_token = generate_jwt_token(payload)

        self.request.COOKIES[jwt_cookie_name()] = jwt_token
        self.middleware.process_request(self.request)

        expected_cache_value = {
            'some_new_role_name': ['some_new_resource_id']
        }
        assert cache.get(cache_key) == expected_cache_value
        assert mock_add_role.call_count == 1
        assert mock_remove_role.call_count == 2

    @patch('edx_rest_framework_extensions.middleware.JwtAuthCookieRoleMiddleware.remove_user_role')
    @patch('edx_rest_framework_extensions.middleware.JwtAuthCookieRoleMiddleware.add_user_role')
    def test_roles_found_in_jwt_previous_role_does_not_exist(self, mock_add_role, mock_remove_role):
        """
        """
        cache_key = '{user_id}:role_metadata'.format(user_id=self.request.user.id)

        payload = generate_unversioned_payload(self.request.user)
        payload.update({
          "roles": [
            "some_new_role_name:some_new_resource_type:some_new_resource_id",
            "some_new_role_name:some_new_resource_type:some_new_resource_id2"
          ]
        })
        jwt_token = generate_jwt_token(payload)

        self.request.COOKIES[jwt_cookie_name()] = jwt_token
        self.middleware.process_request(self.request)

        expected_cache_value = {
            'some_new_role_name': [
                'some_new_resource_id',
                'some_new_resource_id2'
            ]
        }
        assert cache.get(cache_key) == expected_cache_value
        assert mock_add_role.call_count == 2
        assert mock_remove_role.call_count == 0

    @override_settings(ROLE_MAPPING=TEST_ROLE_MAPPING)
    def test_add_user_role_mapping_exists(self):
        assert self.request.user.groups.count() == 0
        assert Group.objects.count() == 0

        # run twice and make sure it does not duplicate role
        for _ in range(2):
            JwtAuthCookieRoleMiddleware.add_user_role(
                'enterprise_learner',
                self.request.user
            )

        assert self.request.user.groups.count() == 1
        assert Group.objects.count() == 1

    @override_settings(ROLE_MAPPING=TEST_ROLE_MAPPING)
    def test_add_user_role_mapping_does_not_exist(self):
        assert self.request.user.groups.count() == 0
        assert Group.objects.count() == 0

        JwtAuthCookieRoleMiddleware.add_user_role(
            'non-existant-role',
            self.request.user
        )

        assert self.request.user.groups.count() == 0
        assert Group.objects.count() == 0

    @override_settings(ROLE_MAPPING=TEST_ROLE_MAPPING)
    def test_remove_user_role_mapping_exists(self):
        group = Group.objects.create(name='enterprise_learner')
        self.request.user.groups.add(group)

        assert self.request.user.groups.count() == 1
        assert Group.objects.count() == 1

        # run twice and make sure user is removed from group;
        # however, group should still remain
        for _ in range(2):
            JwtAuthCookieRoleMiddleware.remove_user_role(
                'enterprise_learner',
                self.request.user
            )

        assert self.request.user.groups.count() == 0
        assert Group.objects.count() == 1
