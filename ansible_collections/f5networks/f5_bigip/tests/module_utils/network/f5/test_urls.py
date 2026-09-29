# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest import TestCase

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.urls import (
    parseStats, build_service_uri
)

fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)

    if path in fixture_data:
        return fixture_data[path]

    with open(path) as f:
        data = f.read()

    try:
        data = json.loads(data)
    except Exception:
        pass

    fixture_data[path] = data
    return data


class TestFunctions(TestCase):
    def test_parse_stats(self):
        vlan_stats = load_fixture('load_stats_vlan.json')
        result1 = parseStats(vlan_stats)

        assert result1['stats']['id'] == 123
        assert result1['stats']['mtu'] == 1500
        assert 'hcInBroadcastPkts' in result1['stats']['stats']['stats']
        assert 'inErrors' in result1['stats']['stats']['stats']

        virtual_stats = load_fixture('load_stats_virtual.json')
        result2 = parseStats(virtual_stats)

        assert result2['stats']['tmName'] == '/Common/for_stats'
        assert result2['stats']['destination'] == '1.1.1.1:80'
        assert 'availabilityState' in result2['stats']['status']
        assert 'accepts' in result2['stats']['syncookie']

        partial1 = {"entries": {"https://localhost/mgmt/tm/net/vlan/~Common~foo1/100": {"description": "foo"}}}
        part_result1 = parseStats(partial1)
        assert part_result1 == ['foo']

    def test_build_service_uri(self):
        result = build_service_uri('foo_url', 'fooPartition', 'fooName')
        assert result == 'foo_url~fooPartition~fooName.app~fooName'

    # Additional edge case tests for parseStats
    def test_parse_stats_with_description(self):
        """Test parseStats with description field"""
        entry = {'description': 'test_value'}
        result = parseStats(entry)
        assert result == 'test_value'

    def test_parse_stats_with_value(self):
        """Test parseStats with value field"""
        entry = {'value': 42}
        result = parseStats(entry)
        assert result == 42

    def test_parse_stats_empty_entries(self):
        """Test parseStats with empty entries"""
        entry = {'entries': {}}
        result = parseStats(entry)
        assert result is None

    def test_parse_stats_nested_stats_entries(self):
        """Test parseStats with nestedStats.entries structure"""
        entry = {
            'nestedStats': {
                'entries': {
                    'key1': {'description': 'value1'},
                    'key2': {'value': 'value2'}
                }
            }
        }
        result = parseStats(entry)
        assert result['key1'] == 'value1'
        assert result['key2'] == 'value2'

    def test_parse_stats_with_dotted_keys(self):
        """Test parseStats with dotted key names"""
        entry = {
            'entries': {
                'stats.inBits': {'value': 1000},
                'stats.outBits': {'value': 2000}
            }
        }
        result = parseStats(entry)
        assert result['stats']['inBits'] == 1000
        assert result['stats']['outBits'] == 2000

    def test_parse_stats_numeric_key_creates_list(self):
        """Test parseStats creates list when key is numeric"""
        entry = {
            'entries': {
                '0': {'value': 'first'},
                '1': {'value': 'second'}
            }
        }
        result = parseStats(entry)
        assert isinstance(result, list)
        assert result[0] == 'first'
        assert result[1] == 'second'

    def test_parse_stats_mixed_keys(self):
        """Test parseStats with numeric key first creates list"""
        entry = {
            'entries': {
                '0': {'value': 'first'},
                'name': {'value': 'named'}
            }
        }
        result = parseStats(entry)
        # When first key is numeric, result is list and subsequent entries appended
        assert isinstance(result, list)
        assert result[0] == 'first'
        assert result[1] == 'named'

    def test_parse_stats_https_localhost_url_key(self):
        """Test parseStats extracts name from https://localhost URL"""
        entry = {
            'entries': {
                'https://localhost/mgmt/tm/net/vlan/~Common~test/100': {'description': 'vlan_stats'}
            }
        }
        result = parseStats(entry)
        assert isinstance(result, list)
        assert result[0] == 'vlan_stats'

    def test_parse_stats_https_localhost_with_named_result(self):
        """Test parseStats with https URL when result is dict"""
        entry = {
            'entries': {
                'https://localhost/mgmt/tm/path/item1': {'description': 'value1'},
                'https://localhost/mgmt/tm/path/item2': {'description': 'value2'}
            }
        }
        result = parseStats(entry)
        assert isinstance(result, dict)
        assert result['item1'] == 'value1'
        assert result['item2'] == 'value2'

    def test_parse_stats_nested_entries_structure(self):
        """Test parseStats with nested entries in nestedStats"""
        entry = {
            'nestedStats': {
                'entries': {
                    'metric.inPackets': {'value': 100},
                    'metric.outPackets': {'value': 200}
                }
            }
        }
        result = parseStats(entry)
        assert result['metric']['inPackets'] == 100
        assert result['metric']['outPackets'] == 200

    def test_parse_stats_deeply_nested(self):
        """Test parseStats with deeply nested structures"""
        entry = {
            'entries': {
                'level1.level2': {'value': 'deep_value'}
            }
        }
        result = parseStats(entry)
        assert result['level1']['level2'] == 'deep_value'

    def test_parse_stats_none_value_in_nested_dict(self):
        """Test parseStats when nested dict value is None"""
        entry = {
            'entries': {
                'stats.metric1': {'value': 'val1'},
                'stats.metric2': {'value': None}
            }
        }
        result = parseStats(entry)
        assert result['stats']['metric1'] == 'val1'
        assert result['stats']['metric2'] is None

    # Additional edge case tests for build_service_uri
    def test_build_service_uri_with_slashes_in_name(self):
        """Test build_service_uri replaces slashes with tildes in name"""
        result = build_service_uri('base', 'part', 'name/with/slashes')
        assert result == 'base~part~name~with~slashes.app~name~with~slashes'

    def test_build_service_uri_empty_partition(self):
        """Test build_service_uri with empty partition"""
        result = build_service_uri('base', '', 'name')
        assert result == 'base~~name.app~name'

    def test_build_service_uri_empty_name(self):
        """Test build_service_uri with empty name"""
        result = build_service_uri('base', 'part', '')
        assert result == 'base~part~.app~'

    def test_build_service_uri_special_characters_in_base(self):
        """Test build_service_uri with special characters in base_uri"""
        result = build_service_uri('http://localhost:8080/api', 'part', 'name')
        assert result == 'http://localhost:8080/api~part~name.app~name'

    def test_build_service_uri_partition_with_slashes(self):
        """Test build_service_uri with slashes in partition"""
        result = build_service_uri('base', 'part/ition', 'name')
        assert result == 'base~part/ition~name.app~name'

    def test_build_service_uri_multiple_slashes_in_name(self):
        """Test build_service_uri with multiple consecutive slashes"""
        result = build_service_uri('base', 'part', 'name//double//slash')
        assert result == 'base~part~name~~double~~slash.app~name~~double~~slash'

    def test_build_service_uri_unicode_characters(self):
        """Test build_service_uri with unicode characters"""
        result = build_service_uri('base', 'part', 'name_ñame')
        assert '~' not in result.split('.app')[0].split('~')[-1].replace('name_ñame', 'X')
        assert result == 'base~part~name_ñame.app~name_ñame'

    def test_build_service_uri_numeric_values(self):
        """Test build_service_uri with numeric string inputs"""
        result = build_service_uri('123', '456', '789')
        assert result == '123~456~789.app~789'

    def test_build_service_uri_with_dots_in_name(self):
        """Test build_service_uri preserves dots in name (only replaces slashes)"""
        result = build_service_uri('base', 'part', 'name.app.test')
        assert result == 'base~part~name.app.test.app~name.app.test'
