"""
Adapter to isolate django-oauth2-provider dependencies
"""

from provider.oauth2 import models
from provider import constants


class DOPAdapter(object):
    """
    Standard interface for working with django-oauth2-provider
    """

    backend = object()

    def create_public_client(self, name, user, redirect_uri, client_id=None):
        """
        Create an oauth client application that is public.
        """
        return models.Client.objects.create(
            name=name,
            user=user,
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_type=constants.PUBLIC,
        )
