""" Tests for settings. """
from django.test import TestCase, override_settings

from edx_rest_framework_extensions.settings import get_setting


class SettingsTests(TestCase):
    """ Tests for settings retrieval. """

    @override_settings(EDX_DRF_EXTENSIONS={})
    def test_get_setting_with_missing_key(self):
        """ Verify the function raises KeyError if the setting is not defined. """
        self.assertRaises(KeyError, get_setting, 'not_defined')

    def test_get_setting(self):
        """ Verify the function returns the value of the specified setting from the EDX_DRF_EXTENSIONS dict. """

        _settings = {
            'some-setting': 'some-value',
            'another-one': False
        }

        with override_settings(EDX_DRF_EXTENSIONS=_settings):
            for key, value in _settings.items():
                self.assertEqual(get_setting(key), value)
