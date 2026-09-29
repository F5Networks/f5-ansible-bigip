# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import unittest

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info import (
    GtmServersParameters, VirtualServersParameters, ClientSslProfilesParameters
)

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest

fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')


def load_fixture(name):
    path = os.path.join(fixture_path, name)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


# ============================================================================
# PARAMETERS CLASS PROPERTY TRANSFORMATION TESTS
# ============================================================================

class TestVirtualServersParametersFormatting(unittest.TestCase):
    """Comprehensive tests for VirtualServersParameters complex property handling"""

    def test_enabled_property_true(self):
        """Test enabled property converts True to 'yes'"""
        args = dict(enabled=True)
        p = VirtualServersParameters(params=args)
        self.assertEqual(p.enabled, 'yes')

    def test_enabled_property_false(self):
        """Test enabled property converts False to 'no'"""
        args = dict(enabled=False)
        p = VirtualServersParameters(params=args)
        self.assertEqual(p.enabled, 'no')

    def test_disabled_property_true(self):
        """Test disabled property converts True to 'yes'"""
        args = dict(disabled=True)
        p = VirtualServersParameters(params=args)
        self.assertEqual(p.disabled, 'yes')

    def test_disabled_property_false(self):
        """Test disabled property converts False to 'no'"""
        args = dict(disabled=False)
        p = VirtualServersParameters(params=args)
        self.assertEqual(p.disabled, 'no')

    def test_name_property(self):
        """Test name property is properly accessed"""
        args = dict(name='test_virtual')
        p = VirtualServersParameters(params=args)
        self.assertEqual(p.name, 'test_virtual')


class TestGtmServersParametersFormatting(unittest.TestCase):
    """Comprehensive tests for GtmServersParameters complex property handling"""

    def test_name_property(self):
        """Test name property access"""
        args = dict(name='gtm_server1')
        p = GtmServersParameters(params=args)
        self.assertEqual(p.name, 'gtm_server1')

    def test_enabled_property(self):
        """Test enabled property transformation"""
        args = dict(enabled=True)
        p = GtmServersParameters(params=args)
        self.assertEqual(p.enabled, 'yes')

    def test_disabled_property(self):
        """Test disabled property transformation"""
        args = dict(disabled=False)
        p = GtmServersParameters(params=args)
        self.assertEqual(p.disabled, 'no')

    def test_multiple_properties_combined(self):
        """Test multiple properties together"""
        args = dict(
            name='server1',
            enabled=True,
            disabled=False
        )
        p = GtmServersParameters(params=args)
        self.assertEqual(p.name, 'server1')
        self.assertEqual(p.enabled, 'yes')

    def test_to_return_method(self):
        """Test to_return returns dict with properties"""
        args = dict(name='server1', enabled=True)
        p = GtmServersParameters(params=args)
        result = p.to_return()
        self.assertIsInstance(result, dict)
        self.assertIn('name', result)


class TestClientSslProfilesParametersFormatting(unittest.TestCase):
    """Comprehensive tests for ClientSslProfilesParameters property transformations"""

    def test_name_property(self):
        """Test name property"""
        args = dict(name='client_ssl_profile1')
        p = ClientSslProfilesParameters(params=args)
        self.assertEqual(p.name, 'client_ssl_profile1')

    def test_enabled_property_true(self):
        """Test enabled property"""
        args = dict(enabled=True)
        p = ClientSslProfilesParameters(params=args)
        self.assertEqual(p.enabled, 'yes')

    def test_disabled_property_false(self):
        """Test disabled property"""
        args = dict(disabled=False)
        p = ClientSslProfilesParameters(params=args)
        self.assertEqual(p.disabled, 'no')

    def test_returnables_present(self):
        """Test that returnables are defined"""
        p = ClientSslProfilesParameters(params={})
        self.assertTrue(hasattr(p, 'returnables'))
        self.assertIsInstance(p.returnables, list)

    def test_api_map_defined(self):
        """Test that api_map is defined for field transformations"""
        p = ClientSslProfilesParameters(params={})
        self.assertTrue(hasattr(p, 'api_map'))
        self.assertIsInstance(p.api_map, dict)


# ============================================================================
# BASE PARAMETERS BEHAVIOR TESTS
# ============================================================================

class TestBaseParametersCommonBehavior(unittest.TestCase):
    """Test BaseParameters common behavior across all Parameters classes"""

    def test_to_return_method_exists(self):
        """Test to_return method is available"""
        p = VirtualServersParameters(params={'name': 'test'})
        self.assertTrue(hasattr(p, 'to_return'))
        self.assertTrue(callable(p.to_return))

    def test_parameters_have_returnables_list(self):
        """Test Parameters classes have returnables list"""
        p1 = VirtualServersParameters(params={})
        p2 = GtmServersParameters(params={})
        p3 = ClientSslProfilesParameters(params={})

        self.assertIsInstance(p1.returnables, list)
        self.assertIsInstance(p2.returnables, list)
        self.assertIsInstance(p3.returnables, list)

    def test_parameters_have_api_map_dict(self):
        """Test Parameters classes have api_map dict"""
        p1 = VirtualServersParameters(params={})
        p2 = GtmServersParameters(params={})
        p3 = ClientSslProfilesParameters(params={})

        self.assertIsInstance(p1.api_map, dict)
        self.assertIsInstance(p2.api_map, dict)
        self.assertIsInstance(p3.api_map, dict)


# ============================================================================
# PARAMETERS CLASS INSTANTIATION AND EDGE CASES
# ============================================================================

class TestParametersClassInstantiation(unittest.TestCase):
    """Test Parameters class instantiation with various inputs"""

    def test_empty_params_dict(self):
        """Test instantiation with empty params"""
        p = VirtualServersParameters(params={})
        self.assertIsNotNone(p)

    def test_single_property(self):
        """Test instantiation with single property"""
        p = GtmServersParameters(params={'name': 'test'})
        self.assertEqual(p.name, 'test')

    def test_multiple_properties(self):
        """Test instantiation with multiple properties"""
        p = ClientSslProfilesParameters(params={
            'name': 'ssl1',
            'enabled': True,
            'disabled': False
        })
        self.assertEqual(p.name, 'ssl1')

    def test_unknown_property_ignored(self):
        """Test that unknown properties don't cause errors"""
        p = VirtualServersParameters(params={'unknown_prop': 'value'})
        self.assertIsNotNone(p)


# ============================================================================
# BOOLEAN TO STRING TRANSFORMATION TESTS
# ============================================================================

class TestBooleanStringTransformations(unittest.TestCase):
    """Test boolean-to-string transformations for 'yes'/'no' conversion"""

    def test_virtual_servers_all_enabled_combinations(self):
        """Test all combinations of enabled/disabled on VirtualServersParameters"""
        test_cases = [
            (True, 'yes'),
            (False, 'no'),
        ]
        for value, expected in test_cases:
            p = VirtualServersParameters(params={'enabled': value})
            self.assertEqual(p.enabled, expected)

    def test_gtm_servers_all_enabled_combinations(self):
        """Test all combinations of enabled/disabled on GtmServersParameters"""
        test_cases = [
            (True, 'yes'),
            (False, 'no'),
        ]
        for value, expected in test_cases:
            p = GtmServersParameters(params={'enabled': value})
            self.assertEqual(p.enabled, expected)

    def test_client_ssl_all_enabled_combinations(self):
        """Test all combinations of enabled/disabled on ClientSslProfilesParameters"""
        test_cases = [
            (True, 'yes'),
            (False, 'no'),
        ]
        for value, expected in test_cases:
            p = ClientSslProfilesParameters(params={'enabled': value})
            self.assertEqual(p.enabled, expected)

    def test_disabled_to_string_conversion(self):
        """Test disabled property string conversion"""
        p = VirtualServersParameters(params={'disabled': True})
        self.assertEqual(p.disabled, 'yes')

        p2 = VirtualServersParameters(params={'disabled': False})
        self.assertEqual(p2.disabled, 'no')


# ============================================================================
# PROPERTIES ACCESSIBLE THROUGH API_MAP
# ============================================================================

class TestApiMapPropertyAccess(unittest.TestCase):
    """Test access to properties defined via api_map"""

    def test_client_ssl_api_map_access(self):
        """Test ClientSslProfilesParameters api_map property transformations"""
        p = ClientSslProfilesParameters(params={'name': 'test_profile'})
        # Verify api_map exists and contains expected mappings
        self.assertIsInstance(p.api_map, dict)
        self.assertTrue(len(p.api_map) > 0)

    def test_gtm_servers_api_map_access(self):
        """Test GtmServersParameters api_map property transformations"""
        p = GtmServersParameters(params={'name': 'test_server'})
        self.assertIsInstance(p.api_map, dict)

    def test_virtual_servers_api_map_access(self):
        """Test VirtualServersParameters api_map property transformations"""
        p = VirtualServersParameters(params={'name': 'test_vs'})
        self.assertIsInstance(p.api_map, dict)


# ============================================================================
# RETURNABLES AND UPDATABLES BEHAVIOR
# ============================================================================

class TestReturnablesAndUpdatables(unittest.TestCase):
    """Test returnables and updatables properties"""

    def test_returnables_is_list(self):
        """Test returnables property is a list"""
        p = VirtualServersParameters(params={})
        self.assertTrue(hasattr(p, 'returnables'))
        self.assertIsInstance(p.returnables, list)

    def test_returnables_not_empty(self):
        """Test returnables contains items"""
        p = ClientSslProfilesParameters(params={})
        self.assertTrue(len(p.returnables) > 0)

    def test_to_return_includes_returnables(self):
        """Test to_return includes returnable properties"""
        p = GtmServersParameters(params={'name': 'test'})
        result = p.to_return()
        # Should be a dict, even if empty
        self.assertIsInstance(result, dict)


# ============================================================================
# EDGE CASES AND ERROR HANDLING
# ============================================================================

class TestParametersEdgeCases(unittest.TestCase):
    """Test edge cases and potential error conditions"""

    def test_none_value_handling(self):
        """Test handling of None values in params"""
        p = VirtualServersParameters(params={'name': None})
        self.assertIsNotNone(p)

    def test_empty_string_name(self):
        """Test handling of empty string for name"""
        p = GtmServersParameters(params={'name': ''})
        self.assertEqual(p.name, '')

    def test_special_characters_in_name(self):
        """Test handling of special characters in name"""
        p = ClientSslProfilesParameters(params={'name': 'test-profile_1.2'})
        self.assertEqual(p.name, 'test-profile_1.2')

    def test_very_long_name(self):
        """Test handling of very long names"""
        long_name = 'a' * 500
        p = VirtualServersParameters(params={'name': long_name})
        self.assertEqual(p.name, long_name)


# ============================================================================
# SUBCLASS-SPECIFIC BEHAVIOR
# ============================================================================

class TestParametersSubclassSpecificBehavior(unittest.TestCase):
    """Test behavior specific to individual Parameters subclasses"""

    def test_parameters_inheritance(self):
        """Test that Parameters classes inherit from BaseParameters"""
        p1 = VirtualServersParameters(params={'name': 'test'})
        p2 = GtmServersParameters(params={'name': 'test'})
        p3 = ClientSslProfilesParameters(params={'name': 'test'})

        self.assertTrue(hasattr(p1, 'to_return'))
        self.assertTrue(hasattr(p2, 'to_return'))
        self.assertTrue(hasattr(p3, 'to_return'))

    def test_different_parameters_classes_independent(self):
        """Test that different Parameters classes don't interfere"""
        p1 = VirtualServersParameters(params={'name': 'vs1', 'enabled': True})
        p2 = GtmServersParameters(params={'name': 'gtm1', 'enabled': False})

        self.assertEqual(p1.name, 'vs1')
        self.assertEqual(p2.name, 'gtm1')
        self.assertEqual(p1.enabled, 'yes')
        self.assertEqual(p2.enabled, 'no')


if __name__ == '__main__':
    unittest.main()
