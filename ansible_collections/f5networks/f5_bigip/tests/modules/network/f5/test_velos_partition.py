# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.velos_tenant import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

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
            name='foo1',
            os_version='1.1.1-5046',
            ipv4_mgmt_address='10.144.140.127/24',
            ipv4_mgmt_gateway='10.144.140.255',
            slots=[5],
            state='present'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'foo1'
        assert p.os_version == '1.1.1-5046'
        assert p.slots == [5]
        assert p.ipv4_mgmt_address == '10.144.140.127/24'
        assert p.ipv4_mgmt_gateway == '10.144.140.255'
        assert p.state == 'present'

    def test_api_parameters(self):
        args = load_fixture('load_partition_info.json')

        p = ApiParameters(params=args)

        assert p.name == 'partition1'
        assert p.os_version == '1.1.1-5046'
        assert p.slots == [5, 6]
        assert p.ipv4_mgmt_address == '10.144.140.127/24'
        assert p.ipv4_mgmt_gateway == '10.144.140.255'
        assert p.state == 'present'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()

    def tearDown(self):
        self.p1.stop()

    def test_partition_create(self, *args):
        set_module_args(dict(
            name='foo1',
            os_version='1.1.1-5046',
            ipv4_mgmt_address='10.144.140.127/24',
            ipv4_mgmt_gateway='10.144.140.255',
            slots=[5],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'tenant': [
            {'name': 'foo', 'config': {
                'image': 'BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle', 'nodes': [1],
                'mgmt-ip': '10.144.140.151', 'gateway': '10.144.140.254', 'vlans': [444],
                'vcpu-cores-per-node': 2, 'memory': 7680, 'cryptos': 'enabled', 'running-state': 'configured'}}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        assert results['changed'] is True
        assert mm.client.post.call_args[1]['data'] == expected

    def test_partition_update(self, *args):
        set_module_args(dict(
            name='foo1',
            slots=[5, 6],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['slots'] == [5, 6]
        assert mm.client.patch.call_count == 2
        assert mm.client.patch.call_args_list[0][0][0] == 'f5-tenants:tenants/tenant=foo/config/vlans'
        assert mm.client.patch.call_args_list[1][0][0] == 'f5-tenants:tenants/tenant=foo/config/running-state'
        assert mm.client.patch.call_args_list[0][1] == {'data': {'vlans': [333, 444]}}
        assert mm.client.patch.call_args_list[1][1] == {'data': {'running-state': 'deployed'}}

    def test_partition_remove(self, *args):
        set_module_args(dict(
            name='foo1',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204, content={}))

        results = mm.exec_module()
        assert results['changed'] is True
        assert mm.client.delete.called