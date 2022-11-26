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
