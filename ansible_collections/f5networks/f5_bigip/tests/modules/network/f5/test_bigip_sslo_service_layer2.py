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
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_service_layer2
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
                           'interface': '1.1', 'create': True, 'tag': 100},
             'to_vlan': {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
                         'interface': '1.1', 'create': True, 'tag': 101}}
        ]
        assert p.networks == [
            {'name': 'ssloN_FEYE1_in', 'path': '/Common/ssloN_FEYE1_in.app/ssloN_FEYE1_in',
             'interface': '1.1', 'tag': 100},
            {'name': 'ssloN_FEYE1_out', 'path': '/Common/ssloN_FEYE1_out.app/ssloN_FEYE1_out',
             'interface': '1.1', 'tag': 101}
        ]
        assert p.devices_ips == [{'ratio': None, 'ip': ['198.19.33.30', '2001:0200:0:0201::1e']}]
        assert p.service_subnet == {'ipv4': '198.19.33.0', 'ipv6': '2001:0200:0:0201::'}
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

    def test_api_parameters_port_remap_returns_value_when_flag_true(self):
        params = {'customService': {'portRemap': True, 'httpPortRemapValue': 9090}}
        p = ApiParameters(params=params)
        assert p.port_remap == 9090

    def test_api_parameters_port_remap_returns_none_when_flag_false(self):
        params = {'customService': {'portRemap': False, 'httpPortRemapValue': 9090}}
        p = ApiParameters(params=params)
        assert p.port_remap is None

    def test_api_parameters_port_remap_returns_none_when_flag_absent(self):
        params = {'customService': {}}
        p = ApiParameters(params=params)
        assert p.port_remap is None

    def test_api_parameters_rules_egress(self):
        rules = [{'name': '/Common/egress-rule', 'value': '/Common/egress-rule'}]
        params = {'customService': {'iRuleListEgress': rules}}
        p = ApiParameters(params=params)
        assert p.rules_egress == rules

    def test_api_parameters_rules_egress_absent_returns_empty_list(self):
        params = {'customService': {}}
        p = ApiParameters(params=params)
        assert p.rules_egress == []

    def test_api_parameters_mode_present(self):
        params = {'customService': {'mode': 'l3_enhanced'}}
        p = ApiParameters(params=params)
        assert p.mode == 'l3_enhanced'

    def test_api_parameters_mode_absent_defaults_to_l3_legacy(self):
        params = {'customService': {}}
        p = ApiParameters(params=params)
        assert p.mode == 'l3_legacy'

    def test_api_parameters_default_persistence_profile(self):
        params = {'customService': {'defaultPersistenceProfile': '/Common/source_addr'}}
        p = ApiParameters(params=params)
        assert p.default_persistence_profile == '/Common/source_addr'

    def test_api_parameters_default_persistence_profile_absent_returns_empty_string(self):
        params = {'customService': {}}
        p = ApiParameters(params=params)
        assert p.default_persistence_profile == ''

    def test_module_parameters_rules_egress(self):
        args = dict(
            name='foobar',
            rules_egress=['/Common/egress-rule-1', '/Common/egress-rule-2'],
        )
        p = ModuleParameters(params=args)
        assert p.rules_egress == [
            {'name': '/Common/egress-rule-1', 'value': '/Common/egress-rule-1'},
            {'name': '/Common/egress-rule-2', 'value': '/Common/egress-rule-2'},
        ]

    def test_module_parameters_rules_egress_returns_none_when_not_provided(self):
        args = dict(name='foobar')
        p = ModuleParameters(params=args)
        assert p.rules_egress is None

    def test_module_parameters_mode(self):
        args = dict(name='foobar', mode='l3_enhanced')
        p = ModuleParameters(params=args)
        assert p.mode == 'l3_enhanced'

    def test_module_parameters_default_persistence_profile(self):
        args = dict(name='foobar', default_persistence_profile='/Common/dest_addr')
        p = ModuleParameters(params=args)
        assert p.default_persistence_profile == '/Common/dest_addr'

    def test_module_parameters_default_persistence_profile_returns_empty_string_when_none(self):
        args = dict(name='foobar')
        p = ModuleParameters(params=args)
        assert p.default_persistence_profile == ''

    def test_module_parameters_service_index_l3_enhanced(self):
        args = dict(name='foobar', mode='l3_enhanced')
        p = ModuleParameters(params=args)
        assert p.service_index == 0

    def test_module_parameters_service_index_l3_legacy_with_offset(self):
        args = dict(name='foobar', ip_offset=3)
        p = ModuleParameters(params=args)
        assert p.service_index == 3

    def test_module_parameters_service_subnet_l3_enhanced(self):
        args = dict(name='foobar', mode='l3_enhanced')
        p = ModuleParameters(params=args)
        assert p.service_subnet == {'ipv4': '198.19.32.0', 'ipv6': '2001:0200:0:200::'}

    def test_module_parameters_devices_ips_l3_enhanced(self):
        args = dict(
            name='foobar',
            mode='l3_enhanced',
            devices=[dict(name='FEYE1', ratio=1, interface_in='1.1', interface_out='1.1')]
        )
        p = ModuleParameters(params=args)
        result = p.devices_ips
        assert result is not None
        assert result[0]['ip'] == []

    def test_module_parameters_port_remap_returns_none_when_not_set(self):
        args = dict(name='foobar')
        p = ModuleParameters(params=args)
        assert p.port_remap is None

    def test_ip_offset_outside_supported_range_raises(self):
        for offset in (-1, 31):
            p = ModuleParameters(params=dict(name='foobar', ip_offset=offset))
            with self.assertRaisesRegex(F5ModuleError, 'range 0 - 30'):
                p.ip_offset

    def test_device_ratio_outside_supported_range_raises(self):
        for ratio in (0, 65536):
            p = ModuleParameters(params=dict(
                name='foobar', ip_offset=1,
                devices=[dict(name='FEYE1', ratio=ratio, interface_in='1.1', interface_out='1.1')]
            ))
            with self.assertRaisesRegex(F5ModuleError, 'range 1 - 65535'):
                p.devices_ips

    def test_timeout_outside_supported_range_raises(self):
        for timeout in (9, 1801):
            p = ModuleParameters(params=dict(name='foobar', timeout=timeout))
            with self.assertRaisesRegex(F5ModuleError, 'between 10 and 1800'):
                p.timeout

    def test_interface_and_service_down_action_choices(self):
        spec = ArgumentSpec()
        device = spec.argument_spec['devices']
        assert device['mutually_exclusive'] == [
            ['vlan_in', 'interface_in'], ['vlan_out', 'interface_out'],
            ['vlan_in', 'tag_in'], ['vlan_out', 'tag_out']
        ]
        assert spec.argument_spec['service_down_action']['choices'] == ['ignore', 'reset', 'drop']


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
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer2.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

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

    def test_create_l2service_object_dump_json_defaults_ip_offset_to_zero(self, *args):
        set_module_args(dict(
            name='layer2a',
            devices=[dict(
                name='FEYE1',
                ratio=1,
                interface_in='1.1',
                tag_in=100,
                interface_out='1.1',
                tag_out=101,
            )],
            service_down_action='reset',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        generated = results['json']
        service_property = next(
            item for item in generated['inputProperties']
            if item['id'] == 'f5-ssl-orchestrator-service'
        )
        custom_service = service_property['value']['customService']

        assert results['changed'] is False
        assert custom_service['managedNetwork']['ipv4']['serviceSubnet'] == '198.19.32.0'
        assert custom_service['managedNetwork']['ipv6']['serviceSubnet'] == '2001:0200:0:0200::'
        assert custom_service['managedNetwork']['ipv4']['serviceIndex'] == 0
        assert custom_service['managedNetwork']['ipv6']['serviceIndex'] == 0
        assert custom_service['loadBalancing']['devices'][0]['ip'] == ['198.19.32.30', '2001:0200:0:0200::1e']

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
        assert results['devices_ips'] == [{'ratio': '1', 'ip': ['198.19.33.30', '2001:0200:0:0201::1e']}]
        assert results['service_down_action'] == 'reset'
        assert results['port_remap'] == 8283
        assert results['service_subnet'] == {'ipv4': '198.19.33.0', 'ipv6': '2001:0200:0:0201::'}

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

    def test_version_check_raises_for_rules_egress_below_13(self, *args):
        set_module_args(dict(
            name='layer2a',
            rules_egress=['/Common/test-rule'],
            devices=[dict(name='FEYE1', ratio=1, interface_in='1.1', interface_out='1.1')],
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'rules_egress parameter is not supported on SSLO versions below 13.0'):
            mm.exec_module()

    def test_version_check_raises_for_mode_below_14(self, *args):
        set_module_args(dict(
            name='layer2a',
            mode='l3_enhanced',
            devices=[dict(name='FEYE1', ratio=1, interface_in='1.1', interface_out='1.1')],
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'mode parameter is not supported on SSLO versions below 14.0'):
            mm.exec_module()

    def test_version_check_raises_for_default_persistence_profile_below_14(self, *args):
        set_module_args(dict(
            name='layer2a',
            default_persistence_profile='/Common/source_addr',
            devices=[dict(name='FEYE1', ratio=1, interface_in='1.1', interface_out='1.1')],
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'default_persistence_profile parameter is not supported on SSLO versions below 14.0'):
            mm.exec_module()

    def test_version_check_raises_when_device_count_exceeds_8_legacy(self, *args):
        devices = [dict(name=f'DEV{i}', ratio=1, interface_in='1.1', interface_out='1.1') for i in range(9)]
        set_module_args(dict(name='layer2a', devices=devices, ip_offset=0))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'Legacy Mode and only supports 8 or less devices'):
            mm.exec_module()

    def test_version_check_raises_for_ip_offset_with_l3_enhanced(self, *args):
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='layer2a',
            mode='l3_enhanced',
            ip_offset=1,
            devices=[dict(name='FEYE1', ratio=1, interface_in='1.1', interface_out='1.1')],
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'ip_offset parameter must not be set when using l3_enhanced mode'):
            mm.exec_module()

    def test_modify_layer2_with_rules_egress(self, *args):
        self.m3.return_value = '13.0'
        set_module_args(dict(
            name='layer2a',
            rules_egress=['/Common/test-egress-rule'],
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_l2_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_l2_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['rules_egress'] == [{'name': '/Common/test-egress-rule', 'value': '/Common/test-egress-rule'}]

    def test_modify_layer2_with_default_persistence_profile(self, *args):
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='layer2a',
            default_persistence_profile='/Common/dest_addr',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_l2_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_l2_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['default_persistence_profile'] == '/Common/dest_addr'

    def test_modify_layer2_vendor_info_immutable(self, *args):
        set_module_args(dict(
            name='layer2a',
            vendor_info='Palo Alto Networks NGFW Inline Layer 2',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        with self.assertRaisesRegex(Exception, 'vendor_info cannot be changed after a service is created'):
            mm.exec_module()

    def test_modify_layer2_mode_immutable(self, *args):
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='layer2a',
            mode='l3_enhanced',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer2.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        with self.assertRaisesRegex(Exception, 'mode cannot be changed after a service is created'):
            mm.exec_module()

    def test_create_l2service_l3_enhanced_dump_json(self, *args):
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='layer2a',
            mode='l3_enhanced',
            devices=[dict(name='FEYE1', ratio=1, interface_in='1.1', tag_in=100, interface_out='1.1', tag_out=101)],
            service_down_action='reset',
            dump_json=True,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        generated = results['json']
        service_property = next(
            item for item in generated['inputProperties']
            if item['id'] == 'f5-ssl-orchestrator-service'
        )
        custom_service = service_property['value']['customService']
        # l3_enhanced always uses serviceIndex 0
        assert custom_service['managedNetwork']['ipv4']['serviceIndex'] == 0
        assert custom_service['managedNetwork']['ipv6']['serviceIndex'] == 0
        assert custom_service['mode'] == 'l3_enhanced'

    def test_update_idempotent(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.want = Mock(dump_json=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()

    def test_unsupported_and_enhanced_device_limit_versions_raise(self):
        self.m3.return_value = '7.0'
        set_module_args(dict(name='layer2a'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        manager = ModuleManager(module=module)
        with self.assertRaisesRegex(F5ModuleError, 'Unsupported SSL Orchestrator version'):
            manager.check_sslo_version()

        self.m3.return_value = '14.0'
        devices = [dict(name=f'DEV{i}', ratio=1, interface_in='1.1', interface_out='1.1') for i in range(51)]
        set_module_args(dict(name='layer2a', mode='l3_enhanced', devices=devices))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        manager = ModuleManager(module=module)
        with self.assertRaisesRegex(F5ModuleError, '50 or less devices'):
            manager.check_sslo_version()

    def test_exists_error_raises(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_layer2a')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='exists failed')))

        with self.assertRaisesRegex(F5ModuleError, 'exists failed'):
            manager.exists()

    def test_create_update_and_remove_errors_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(dump_json=False)
        manager.changes = Mock(to_return=Mock(return_value={}))
        manager.add_json_metadata = Mock(side_effect=lambda payload=None: payload or {})
        manager.add_create_values = Mock(side_effect=lambda payload: payload)
        manager.add_missing_options = Mock(side_effect=lambda payload: payload)
        manager.client = Mock(post=Mock(return_value=dict(code=500, contents='operation failed')))

        with patch.object(bigip_sslo_service_layer2, 'process_json', return_value={}):
            for operation in (manager.create_on_device, manager.update_on_device, manager.remove_from_device):
                with self.assertRaisesRegex(F5ModuleError, 'operation failed'):
                    operation()

    def test_read_current_error_and_missing_item_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_layer2a')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='read failed')))

        with self.assertRaisesRegex(F5ModuleError, 'read failed'):
            manager.read_current_from_device()

        manager.client.get.return_value = dict(code=200, contents={'items': []})
        with self.assertRaisesRegex(F5ModuleError, 'items'):
            manager.read_current_from_device()

    def test_wait_for_task_error_and_timeout_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(timeout=(1, 1))
        manager.operation = 'CREATE'
        manager.delete_failed_operation_on_device = Mock()
        manager._check_task_on_device = Mock(return_value={'state': 'ERROR', 'error': 'task failed'})

        with self.assertRaisesRegex(F5ModuleError, 'task failed'):
            manager.wait_for_task('task-id')
        manager.delete_failed_operation_on_device.assert_called_once_with('task-id')

        manager._check_task_on_device = Mock(return_value={'state': 'RUNNING'})
        with self.assertRaisesRegex(F5ModuleError, 'Module timeout reached'):
            manager.wait_for_task('task-id')

    def test_check_task_on_device_error_raises(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='task lookup failed')))

        with self.assertRaisesRegex(F5ModuleError, 'task lookup failed'):
            manager._check_task_on_device('task-id')

    def test_main_function_success(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.return_value = {'changed': False}
        with patch.object(bigip_sslo_service_layer2, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_layer2, 'Connection'), \
                patch.object(bigip_sslo_service_layer2, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_layer2, 'ModuleManager', return_value=manager):
            bigip_sslo_service_layer2.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('service failed')
        with patch.object(bigip_sslo_service_layer2, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_layer2, 'Connection'), \
                patch.object(bigip_sslo_service_layer2, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_layer2, 'ModuleManager', return_value=manager):
            bigip_sslo_service_layer2.main()

        module.fail_json.assert_called_once_with(msg='service failed')
