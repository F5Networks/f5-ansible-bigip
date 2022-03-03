# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_interface import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import set_module_args


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


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            name="2/1.0",
            trunk_vlans=[444],
            state='present'
        )
        p = ModuleParameters(params=args)
        assert p.name == '2/1.0'
        assert p.switched_vlan == [444]

    def test_api_parameters(self):
        args = load_fixture('load_velos_partition_interface_config.json')

        p = ApiParameters(params=args)

        assert p.interface_type == 'ethernetCsmacd'
        assert p.switched_vlan == [444]


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_interface.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()

    def tearDown(self):
        self.p1.stop()

    def test_partition_interface_create_switched_vlan(self, *args):
        set_module_args(dict(
            name="2/1.0",
            trunk_vlans=[444],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))
        fixdata = []
        fixdata.append(load_fixture("load_velos_partition_interface_config.json"))
        newdata = {
            "openconfig-interfaces:interface": fixdata,
        }
        mm.client.get = Mock(
            return_value=dict(code=200, contents=dict(newdata)))

        results = mm.exec_module()
        assert results['changed'] is False

    def test_partition_interface_update_switched_vlan(self, *args):
        set_module_args(dict(
            name="2/1.0",
            trunk_vlans=[444, 555],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents=""))
        fixdata = []
        fixdata.append(load_fixture("load_velos_partition_interface_config.json"))
        newdata = {
            "openconfig-interfaces:interface": fixdata,
        }
        mm.client.get = Mock(
            return_value=dict(code=200, contents=dict(newdata)))
        mm.client.delete = Mock(return_value=dict(code=204, contents=""))

        results = mm.exec_module()

        assert results['changed'] is True

    def test_partition_interface_delete_switched_vlan(self, *args):
        set_module_args(dict(
            name="2/1.0",
            trunk_vlans=[444],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204, contents=""))
        mm.client.get = Mock(
            return_value=dict(code=200,
                              contents=load_fixture("load_velos_partition_interface_swichedvlan_config.json")))
        fixdata = []
        fixdata.append(load_fixture("load_velos_partition_interface_config.json"))
        newdata = {
            "openconfig-interfaces:interface": fixdata,
        }
        mm.client.get = Mock(
            return_value=dict(code=200, contents=dict(newdata)))

        results = mm.exec_module()

        assert results['changed'] is True
