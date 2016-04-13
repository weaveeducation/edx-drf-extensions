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
