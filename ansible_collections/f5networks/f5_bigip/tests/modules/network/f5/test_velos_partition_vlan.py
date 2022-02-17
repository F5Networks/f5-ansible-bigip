# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_vlan import (
    ModuleParameters, ArgumentSpec, ModuleManager
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
    def test_module_parameters_name_missing(self):
        args = dict(
            vlan_id=1234
        )

        p = ModuleParameters(params=args)
        assert p.vlan_id == 1234
        assert p.name == "1234"

    def test_module_parameters_name_present(self):
        args = dict(
            vlan_id=1234,
            name='foobar'
        )

        p = ModuleParameters(params=args)
        assert p.vlan_id == 1234
        assert p.name == "foobar"

    def test_module_parameters_invalid_vlan(self):
        args = dict(
            vlan_id=99999
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError):
            p.vlan_id()


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition_vlan.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()

    def tearDown(self):
        self.p1.stop()

    def test_vlan_create_name_provided(self, *args):
        set_module_args(dict(
            name="foobar",
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-vlan:vlans': {'vlan': [{'vlan-id': 1234, 'config': {'vlan-id': 1234, 'name': 'foobar'}}]}}
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()
        assert results['changed'] is True
        assert mm.client.patch.call_args[1]['data'] == expected

    def test_vlan_create_name_missing(self, *args):
        set_module_args(dict(
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-vlan:vlans': {'vlan': [{'vlan-id': 1234, 'config': {'vlan-id': 1234, 'name': '1234'}}]}}
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value=dict(code=201, contents=""))

        results = mm.exec_module()
        assert results['changed'] is True
        mm.client.patch.assert_called_once_with('/', data=expected)

    def test_vlan_update_name(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="new_name",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents=""))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture("load_velos_vlan_config.json")))

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.patch.assert_called_once_with(
            '/openconfig-vlan:vlans/vlan=3333/config/name', data=dict(name='new_name')
        )

    def test_vlan_delete(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204, contents=""))

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.delete.assert_called_once_with('/openconfig-vlan:vlans/vlan=3333')
