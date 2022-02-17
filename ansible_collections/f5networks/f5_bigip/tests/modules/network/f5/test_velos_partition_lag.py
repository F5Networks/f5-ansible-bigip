# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_lag import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import set_module_args

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

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
            name="Arista",
            trunk_vlans=[444],
            state='present'
        )
        p = ModuleParameters(params=args)
        assert p.name == 'Arista'
        assert p.switched_vlan == [444]

    def test_api_parameters(self):
        args = load_fixture('load_velos_partition_lag_config.json')

        p = ApiParameters(params=args)

        assert p.interface_type == 'ieee8023adLag'
        assert p.switched_vlan == [444]


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_lag.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()

    def tearDown(self):
        self.p1.stop()

    def test_partition_interface_create_switched_vlan(self, *args):
        set_module_args(dict(
            name="Arista",
            trunk_vlans=[444],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-vlan:switched-vlan': {'config': {'trunk-vlans': [444]}}}
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))
        fixdata = []
        fixdata.append(load_fixture("load_velos_partition_lag_config.json"))
        newdata = {
            "openconfig-interfaces:interfaces": {
                "interface": fixdata
            }
        }
        intdata = {
            "openconfig-interfaces:interfaces": {
                "interface": fixdata
            }
        }
        payload = {
            "openconfig-if-ethernet:config": {
                "openconfig-if-aggregate:aggregate-id": "2/1.0"
            }
        }
        mm.client.get = Mock(
            return_value=dict(code=200, contents=dict(newdata)))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=dict(intdata)))
        # mm.client.patch = Mock(return_value=dict(code=204, contents=""))

        results = mm.exec_module()
        assert results['changed'] is True

    def test_partition_interface_delete_switched_vlan(self, *args):
        set_module_args(dict(
            name="Arista",
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
            return_value=dict(code=200, contents=load_fixture("load_velos_partition_lag_config.json")))
        fixdata = []
        fixdata.append(load_fixture("load_velos_partition_lag_config.json"))
        intf_list = ["2/1.0"]
        config = dict(contents=load_fixture("load_velos_partition_lag_config.json"))
        config.update(config_members=intf_list)
        mm.read_current_from_device = Mock(
            return_value=dict(code=200, contents=config))
        mm.remove_from_device = Mock(
            return_value=dict(code=200, contents=config))
        results = mm.exec_module()
        assert results['changed'] is True
