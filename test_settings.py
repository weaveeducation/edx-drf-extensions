"""
These settings are here to use during tests, because django requires them.

In a real-world use case, apps in this project are installed into other
Django applications, so these settings will not be used.
"""

SECRET_KEY = 'insecure-secret-key'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django_nose',
    'edx_rest_framework_extensions',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'default.db',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
    }
}

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

EDX_DRF_EXTENSIONS = {}

JWT_AUTH = {
    'JWT_AUDIENCE': 'test-aud',
    'JWT_ISSUER': 'test-iss',
    'JWT_SECRET_KEY': 'tell-no-one',
}
