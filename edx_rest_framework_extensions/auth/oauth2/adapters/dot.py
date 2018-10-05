"""
Adapter to isolate django-oauth-toolkit dependencies
"""

from oauth2_provider import models


class DOTAdapter(object):
    """
    Standard interface for working with django-oauth-toolkit
    """

    backend = object()

    def create_public_client(self, name, user, redirect_uri, client_id=None,
                             grant_type=models.Application.GRANT_PASSWORD):
        """
        Create an oauth client application that is public.
        """
        return models.Application.objects.create(
            name=name,
            user=user,
            client_id=client_id,
            client_type=models.Application.CLIENT_PUBLIC,
            authorization_grant_type=grant_type,
            redirect_uris=redirect_uri,
        )
