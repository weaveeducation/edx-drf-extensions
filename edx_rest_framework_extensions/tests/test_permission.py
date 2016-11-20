""" Tests for permission classes. """

import ddt
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase

from edx_rest_framework_extensions.permissions import IsSuperuser
from edx_rest_framework_extensions.tests import factories


@ddt.ddt
class IsSuperuserTests(TestCase):
    """ Tests for the IsSuperuser permission class. """

    @ddt.data(True, False)
    def test_has_permission(self, has_permission):
        """ Verify the method only returns True if the user is a superuser. """
        request = RequestFactory().get('/')
        request.user = factories.UserFactory(is_superuser=has_permission)
        permission = IsSuperuser()
        self.assertEqual(permission.has_permission(request, None), has_permission)

    @ddt.data(None, AnonymousUser())
    def test_has_permission_with_invalid_users(self, user):
        """ Verify the method returns False if the request's user is not a real user. """
        request = RequestFactory().get('/')
        request.user = user
        permission = IsSuperuser()
        self.assertFalse(permission.has_permission(request, None))


@ddt.ddt
class JwtScopePermissionsTests(TestCase):
    """ Tests for the JwtScopePermissions permission class. """

    def test_get_action_map(self):
        """ Verify the method returns the appropriate action map, depending on if the view has an override. """
        # Test the default
        # Test with a view override
        self.fail()

    def test_get_resource(self):
        """ Verify the method returns either the value set on the view or the value
        determined from the view's serializer. """
        self.fail()

    def test_get_required_scopes(self):
        """ Verify the method returns the list of scopes required to access a view endpoint."""
        # TODO Use DDT here.
        self.fail()

    def test_has_permission(self):
        """ Verify the method returns True if the user has permission to access the endpoint. """
        self.fail()

    def test_has_permission_with_invalid_authenticator(self):
        """ Verify the method returns True if the request is not authenticated by `JwtAuthentication`. """
        self.fail()

    def test_has_permission_with_no_authentication(self):
        """ Verify the method returns False if the request has not been authenticated. """
        self.fail()
