# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer3 import (
    ModuleParameters, ApiParameters, ArgumentSpec, Difference, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_service_layer3
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
            name="layer3a",
            devices_to=dict(
                interface='1.1',
                tag=40,
                self_ip='198.19.64.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.64.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.64.30'), dict(ip='198.19.64.31')],
            service_down_action='ignore',
            port_remap=8081,
            ip_family='ipv4'
        )

        p = ModuleParameters(params=args)
        assert p.devices == [{'ip': '198.19.64.30', 'port': 80}, {'ip': '198.19.64.31', 'port': 80}]
        assert p.devices_to == {
            'name': 'ssloN_layer3a_in', 'path': '/Common/ssloN_layer3a_in.app/ssloN_layer3a_in',
            'self_ip': '198.19.64.7',
            'netmask': '255.255.255.128', 'network': '198.19.64.0', 'interface': '1.1', 'tag': 40
        }
        assert p.devices_from == {
            'name': 'ssloN_layer3a_out', 'path': '/Common/ssloN_layer3a_out.app/ssloN_layer3a_out',
            'self_ip': '198.19.64.245',
            'netmask': '255.255.255.128', 'network': '198.19.64.128', 'interface': '1.1', 'tag': 50
        }
        assert p.name == 'ssloS_layer3a'
        assert p.port_remap == 8081

    def test_api_parameters(self):
        args = load_fixture('return_sslo_layer3_params.json')
        p = ApiParameters(params=args)

        assert p.devices == [{'ip': '198.19.64.30', 'port': 80}, {'ip': '198.19.64.31', 'port': 80}]
        assert p.devices_to == {
            'name': 'ssloN_layer3a_in', 'path': '/Common/ssloN_layer3a_in.app/ssloN_layer3a_in', 'self_ip': '198.19.64.7',
            'netmask': '255.255.255.128', 'network': '198.19.64.0', 'interface': '1.1', 'tag': 40
        }
        assert p.devices_from == {
            'name': 'ssloN_layer3a_out', 'path': '/Common/ssloN_layer3a_out.app/ssloN_layer3a_out', 'self_ip': '198.19.64.245',
            'netmask': '255.255.255.128', 'network': '198.19.64.128', 'interface': '1.1', 'tag': 50
        }
        assert p.monitor == '/Common/gateway_icmp'
        assert p.ip_family == 'ipv4'
        assert p.port_remap == 8081
        assert p.service_down_action == 'ignore'

    def test_module_parameters_ipv6_netmask_collapsed(self):
        args = dict(
            name="layer3a",
            devices_to=dict(vlan='/Common/l3-in', self_ip='2017:10:10:14::23', netmask='ffff:ffff:ffff:ffff::'),
            devices_from=dict(vlan='/Common/l3-out', self_ip='2017:10:10:15::23', netmask='ffff:ffff:ffff:ffff::'),
            devices=[dict(ip='2017:10:10:14::11')],
            ip_family='ipv6'
        )
        p = ModuleParameters(params=args)
        assert p.devices_to['netmask'] == 'ffff:ffff:ffff:ffff::'
        assert p.devices_from['netmask'] == 'ffff:ffff:ffff:ffff::'

    def test_module_parameters_ipv6_netmask_expanded_normalized(self):
        args = dict(
            name="layer3a",
            devices_to=dict(vlan='/Common/l3-in', self_ip='2017:10:10:14::23', netmask='ffff:ffff:ffff:ffff:0:0:0:0'),
            devices_from=dict(vlan='/Common/l3-out', self_ip='2017:10:10:15::23', netmask='ffff:ffff:ffff:ffff:0:0:0:0'),
            devices=[dict(ip='2017:10:10:14::11')],
            ip_family='ipv6'
        )
        p = ModuleParameters(params=args)
        assert p.devices_to['netmask'] == 'ffff:ffff:ffff:ffff::'
        assert p.devices_from['netmask'] == 'ffff:ffff:ffff:ffff::'

    def test_module_parameters_rules_egress(self):
        args = dict(
            name='layer3a',
            rules_egress=['/Common/test-egress-rule-1', '/Common/test-egress-rule-2'],
        )
        p = ModuleParameters(params=args)
        expected = [
            {'name': '/Common/test-egress-rule-1', 'value': '/Common/test-egress-rule-1'},
            {'name': '/Common/test-egress-rule-2', 'value': '/Common/test-egress-rule-2'},
        ]
        assert p.rules_egress == expected

    def test_module_parameters_rules_egress_returns_none_when_not_provided(self):
        args = dict(name='layer3a')
        p = ModuleParameters(params=args)
        assert p.rules_egress is None

    def test_module_parameters_default_persistence_profile(self):
        args = dict(name='layer3a', default_persistence_profile='/Common/source_addr')
        p = ModuleParameters(params=args)
        assert p.default_persistence_profile == '/Common/source_addr'

    def test_module_parameters_default_persistence_profile_returns_empty_string_when_none(self):
        args = dict(name='layer3a')
        p = ModuleParameters(params=args)
        assert p.default_persistence_profile == ''

    def test_api_parameters_port_remap_returns_none_when_flag_is_false(self):
        params = {'customService': {'portRemap': False, 'httpPortRemapValue': 8081}}
        p = ApiParameters(params=params)
        assert p.port_remap is None

    def test_api_parameters_port_remap_returns_value_when_flag_is_true(self):
        params = {'customService': {'portRemap': True, 'httpPortRemapValue': 9090}}
        p = ApiParameters(params=params)
        assert p.port_remap == 9090

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

    def test_api_parameters_default_persistence_profile(self):
        params = {'customService': {'defaultPersistenceProfile': '/Common/source_addr'}}
        p = ApiParameters(params=params)
        assert p.default_persistence_profile == '/Common/source_addr'

    def test_api_parameters_default_persistence_profile_absent_returns_empty_string(self):
        params = {'customService': {}}
        p = ApiParameters(params=params)
        assert p.default_persistence_profile == ''

    def test_devices_invalid_port_raises(self):
        p = ModuleParameters(params=dict(name='layer3a', devices=[dict(ip='198.19.64.30', port=65536)]))

        with self.assertRaisesRegex(F5ModuleError, '0 - 65535'):
            p.devices

    def test_vlan_network_configuration(self):
        p = ModuleParameters(params=dict(
            name='layer3a',
            devices_to=dict(vlan='/Common/inbound', self_ip='198.19.64.7', netmask='255.255.255.128'),
            devices_from=dict(vlan='/Common/outbound', self_ip='198.19.64.245', netmask='255.255.255.128')
        ))

        assert p.devices_to['vlan'] == '/Common/inbound'
        assert p.devices_from['vlan'] == '/Common/outbound'
        assert p.devices_to['network'] == '198.19.64.0'
        assert p.devices_from['network'] == '198.19.64.128'

    def test_timeout_outside_supported_range_raises(self):
        for timeout in (9, 1801):
            p = ModuleParameters(params=dict(name='layer3a', timeout=timeout))
            with self.assertRaisesRegex(F5ModuleError, 'between 10 and 1800'):
                p.timeout

    def test_service_down_action_choices(self):
        spec = ArgumentSpec()
        assert spec.argument_spec['service_down_action']['choices'] == ['ignore', 'reset', 'drop']


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer3.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer3.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '7.5'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_layer3.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_layer3_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_layer3_create_generated.json')
        set_module_args(dict(
            name="layer3a",
            devices_to=dict(
                interface='1.1',
                tag=40,
                self_ip='198.19.64.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.64.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.64.30'), dict(ip='198.19.64.31')],
            service_down_action='ignore',
            port_remap=8081,
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

    def test_modify_layer3_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_layer3_modify_generated.json')
        set_module_args(dict(
            name="layer3a",
            snat='snatlist',
            snat_list=['198.19.64.10', '198.19.64.11', '198.19.64.12'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_layer3_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l3_delete_generated.json')
        set_module_args(dict(
            name='layer3a',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3_modified.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(return_value=exists)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_layer3_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="layer3a",
            devices_to=dict(
                interface='1.1',
                tag=40,
                self_ip='198.19.64.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.64.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.64.30'), dict(ip='198.19.64.31')],
            service_down_action='ignore',
            port_remap=8081
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_layer3_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_layer3_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['devices_to'] == {
            'interface': '1.1', 'tag': 40, 'self_ip': '198.19.64.7', 'netmask': '255.255.255.128'
        }
        assert results['devices_from'] == {
            'interface': '1.1', 'tag': 50, 'self_ip': '198.19.64.245', 'netmask': '255.255.255.128'
        }
        assert results['devices'] == [{'ip': '198.19.64.30', 'port': 80}, {'ip': '198.19.64.31', 'port': 80}]
        # assert results['ip_family'] == 'ipv4'
        assert results['service_down_action'] == 'ignore'
        assert results['port_remap'] == 8081

    def test_modify_layer3_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="layer3a",
            snat='snatlist',
            snat_list=['198.19.64.10', '198.19.64.11', '198.19.64.12'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_layer3_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_layer3_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['snat'] == 'snatlist'
        assert results['snat_list'] == ['198.19.64.10', '198.19.64.11', '198.19.64.12']

    def test_modify_layer3_service_vendor_info_immutable(self, *args):
        set_module_args(dict(
            name='layer3a',
            vendor_info='Palo Alto Networks NGFW Inline Layer 3'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
        mm.client.get = Mock(side_effect=[exists, exists])

        with self.assertRaisesRegex(Exception, 'vendor_info cannot be changed after a service is created'):
            mm.exec_module()

    def test_delete_layer3_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_l3_delete_generated.json')
        set_module_args(dict(
            name='layer3a',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3_modified.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_layer3_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_layer3_delete_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_version_check_raises_for_rules_egress_below_13(self, *args):
        # sslo_version mock returns '7.5' by default (< 13.0), so rules_egress must raise
        set_module_args(dict(
            name='layer3a',
            rules_egress=['/Common/test-rule'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'rules_egress parameter requires SSL Orchestrator version 13.0'):
            mm.exec_module()

    def test_version_check_raises_for_default_persistence_profile_below_14(self, *args):
        # sslo_version mock returns '7.5' by default (< 14.0), so default_persistence_profile must raise
        set_module_args(dict(
            name='layer3a',
            default_persistence_profile='/Common/source_addr',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'default_persistence_profile parameter requires SSL Orchestrator version 14.0'):
            mm.exec_module()

    def test_modify_layer3_with_rules_egress(self, *args):
        # Override version to 13.0 so rules_egress is accepted
        self.m3.return_value = '13.0'
        set_module_args(dict(
            name='layer3a',
            rules_egress=['/Common/test-egress-rule-1'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_layer3_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_layer3_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['rules_egress'] == ['/Common/test-egress-rule-1']

    def test_modify_layer3_with_default_persistence_profile(self, *args):
        # Override version to 14.0 so default_persistence_profile is accepted
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='layer3a',
            default_persistence_profile='/Common/source_addr',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_layer3_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_layer3_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['default_persistence_profile'] == '/Common/source_addr'

    def test_modify_layer3_with_port_remap_disabled_in_api(self, *args):
        # Verifies that when portRemap=False on the device, port_remap is not returned
        # and a subsequent modify with port_remap set causes a change
        self.m3.return_value = '9.0'
        set_module_args(dict(
            name='layer3a',
            port_remap=9090,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_layer3_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_layer3_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['port_remap'] == 9090

    def test_update_idempotent(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.want = Mock(dump_json=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()

    def test_immutable_networks_raise(self):
        want = Mock(
            devices_to={'name': 'toNetwork', 'self_ip': '198.19.64.8', 'netmask': '255.255.255.128'},
            devices_from={'name': 'fromNetwork', 'self_ip': '198.19.64.246', 'netmask': '255.255.255.128'},
            use_exist_selfip=False
        )
        have = Mock(
            devices_to={'name': 'toNetwork', 'self_ip': '198.19.64.7', 'netmask': '255.255.255.128'},
            devices_from={'name': 'fromNetwork', 'self_ip': '198.19.64.245', 'netmask': '255.255.255.128'}
        )
        diff = Difference(want, have)

        with self.assertRaisesRegex(F5ModuleError, 'Self-IPs are immutable'):
            diff.devices_to
        with self.assertRaisesRegex(F5ModuleError, 'Self-IPs are immutable'):
            diff.devices_from

    def test_unsupported_sslo_version_raises(self):
        self.m3.return_value = '7.0'
        set_module_args(dict(name='layer3a'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        manager = ModuleManager(module=module)

        with self.assertRaisesRegex(F5ModuleError, 'Unsupported SSL Orchestrator version'):
            manager.check_sslo_version()

    def test_create_requires_networks_devices_and_snat_pool(self):
        manager = ModuleManager.__new__(ModuleManager)
        for missing in ('devices_to', 'devices_from', 'devices'):
            manager.want = Mock(devices_to=object(), devices_from=object(), devices=object(), snat=None)
            setattr(manager.want, missing, None)
            with self.assertRaisesRegex(F5ModuleError, 'devices_to'):
                manager.check_for_required_create_parameters()

        manager.want = Mock(devices_to=object(), devices_from=object(), devices=object(), snat='existingSNAT', snat_pool=None)
        with self.assertRaisesRegex(F5ModuleError, 'snat_pool'):
            manager.check_for_required_create_parameters()

    def test_exists_error_raises(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_layer3a')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='exists failed')))

        with self.assertRaisesRegex(F5ModuleError, 'exists failed'):
            manager.exists()

    def test_create_update_and_remove_errors_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(dump_json=False)
        manager.changes = Mock(to_return=Mock(return_value={}))
        manager.removals = Mock(to_return=Mock(return_value={}))
        manager.add_json_metadata = Mock(side_effect=lambda payload=None: payload or {})
        manager.add_create_values = Mock(side_effect=lambda payload: payload)
        manager.add_missing_options = Mock(side_effect=lambda payload: payload)
        manager.client = Mock(post=Mock(return_value=dict(code=500, contents='operation failed')))

        with patch.object(bigip_sslo_service_layer3, 'process_json', return_value={}):
            for operation in (manager.create_on_device, manager.update_on_device, manager.remove_from_device):
                with self.assertRaisesRegex(F5ModuleError, 'operation failed'):
                    operation()

    def test_read_current_error_and_missing_item_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_layer3a')
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
        with patch.object(bigip_sslo_service_layer3, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_layer3, 'Connection'), \
                patch.object(bigip_sslo_service_layer3, 'HAS_NETADDR', True), \
                patch.object(bigip_sslo_service_layer3, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_layer3, 'ModuleManager', return_value=manager):
            bigip_sslo_service_layer3.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('service failed')
        with patch.object(bigip_sslo_service_layer3, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_layer3, 'Connection'), \
                patch.object(bigip_sslo_service_layer3, 'HAS_NETADDR', True), \
                patch.object(bigip_sslo_service_layer3, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_layer3, 'ModuleManager', return_value=manager):
            bigip_sslo_service_layer3.main()

        module.fail_json.assert_called_once_with(msg='service failed')
