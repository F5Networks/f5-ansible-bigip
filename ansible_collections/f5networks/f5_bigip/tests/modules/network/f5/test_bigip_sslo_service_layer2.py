# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer2 import (
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
            name='foobar',
            devices=[dict(
                name='FEYE1',
                interface_in='1.1',
                tag_in=100,
                interface_out='1.1',
                tag_out=101)
            ],
            service_down_action='reset',
            ip_offset=1,
            port_remap=8283,
            rules=['/Common/rule1', '/Common/rule2']
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloS_foobar'
        assert p.interfaces == [
            {'from_vlan': {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
                           'interface': '1.1', 'tag': 100},
             'to_vlan': {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
                         'interface': '1.1', 'tag': 101}}
        ]
        assert p.networks == [
            {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
             'interface': '1.1', 'tag': 100},
            {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
             'interface': '1.1', 'tag': 101}
        ]
        assert p.devices_ips == [{'ratio': None, 'ip': ['198.19.33.30', '2001:0200:0:201::1e']}]
        assert p.service_subnet == {'ipv4': '198.19.33.0', 'ipv6': '2001:0200:0:201::'}
        assert p.ip_offset == 1
        assert p.rules == [
            {'name': '/Common/rule1', 'value': '/Common/rule1'},
            {'name': '/Common/rule2', 'value': '/Common/rule2'}
        ]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_l2_params.json')
        p = ApiParameters(params=args)

        assert p.interfaces == [
            {'from_vlan': {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
                           'interface': '1.1', 'tag': 100},
             'to_vlan': {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
                         'interface': '1.1', 'tag': 101}}
        ]
        assert p.networks == [
            {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
             'interface': '1.1', 'tag': 100},
            {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
             'interface': '1.1', 'tag': 101}
        ]
        assert p.devices_ips == [{'ratio': '1', 'ip': ['198.19.33.30', '2001:0200:0:201::1e']}]
        assert p.service_subnet == {'ipv4': '198.19.33.0', 'ipv6': '2001:0200:0:201::'}


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer2.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer2.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '7.5'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_l2service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l2_create_generated.json')
        set_module_args(dict(
            name='layer2a',
            devices=[dict(
                name='FEYE1',
                ratio=1,
                interface_in='1.1',
                tag_in=100,
                interface_out='1.1',
                tag_out=101,
            )
            ],
            service_down_action='reset',
            ip_offset=1,
            port_remap=8283,
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_l2service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l2_modify_generated.json')
        set_module_args(dict(
            name='layer2a',
            devices=[dict(
                name='FEYE1',
                ratio=1,
                vlan_in='/Common/L2service_vlan_in',
                interface_out='1.1',
                tag_out=101,
            )
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_l2service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l2_delete_generated.json')
        set_module_args(dict(
            name='layer2a',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2_modified.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_l2service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='layer2a',
            devices=[dict(
                name='FEYE1',
                ratio=1,
                interface_in='1.1',
                tag_in=100,
                interface_out='1.1',
                tag_out=101)
            ],
            service_down_action='reset',
            ip_offset=1,
            port_remap=8283
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_l2_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_l2_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['interfaces'] == [
            {'from_vlan': {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
                           'interface': '1.1', 'tag': 100, 'create': True},
             'to_vlan': {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
                         'interface': '1.1', 'tag': 101, 'create': True}}
        ]
        assert results['networks'] == [
            {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
             'interface': '1.1', 'tag': 100},
            {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
             'interface': '1.1', 'tag': 101}
        ]
        assert results['devices_ips'] == [{'ratio': '1', 'ip': ['198.19.33.30', '2001:0200:0:201::1e']}]
        assert results['service_down_action'] == 'reset'
        assert results['port_remap'] == 8283
        assert results['service_subnet'] == {'ipv4': '198.19.33.0', 'ipv6': '2001:0200:0:201::'}

    def test_modify_l2service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='layer2a',
            devices=[dict(
                name='FEYE1',
                ratio=1,
                vlan_in='/Common/L2service_vlan_in',
                interface_out='1.1',
                tag_out=101
            )
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_l2_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_l2_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['interfaces'] == [
            {'from_vlan': {'name': 'ssloN_FEYE1_in', 'path': '/Common/L2service_vlan_in', 'create': False},
             'to_vlan': {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
                         'interface': '1.1', 'tag': 101, 'create': False,
                         'block_id': '7e47d7b1-eef7-4065-80a4-d5b910a6b9f6'}}
        ]
        assert results['networks'] == [
            {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
             'interface': '1.1', 'tag': 101, 'block_id': '7e47d7b1-eef7-4065-80a4-d5b910a6b9f6'}
        ]

    def test_delete_l2service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='layer2a',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2_modified.json'))
        # Override methods to force specific logic in the module to happen
        done = dict(code=200, contents=load_fixture('reply_sslo_l2_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_l2_delete_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
