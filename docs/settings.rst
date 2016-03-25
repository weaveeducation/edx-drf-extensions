Settings
========

All settings for this package reside in a dict, `EDX_DRF_EXTENSIONS`. Within this dict, the following keys should be
specified, depending on the functionality you are using.


BearerAuthentication
--------------------

.. py:currentmodule:: edx_rest_framework_extensions

These settings are used by the :class:`~authentication.BearerAuthentication` class.

``OAUTH2_USER_INFO_URL``
~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``None``

URL of an endpoint on the OAuth2 provider where :class:`~authentication.BearerAuthentication` can retrieve details
about the user associated with the provided access token. This endpoint should return a JSON object with user details
and ``HTTP 200`` if, and only if, the access token is valid. See
:meth:`BearerAuthentication.process_user_info_response() <authentication.BearerAuthentication.process_user_info_response>`
for an example of the expected data format.
