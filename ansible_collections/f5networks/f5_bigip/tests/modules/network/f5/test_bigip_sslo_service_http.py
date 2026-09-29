# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_http import (
    ModuleParameters, ApiParameters, ArgumentSpec, Difference, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_sslo_service_http
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
            name='proxy1a',
            devices_to=dict(
                vlan='/Common/proxy1a-in-vlan',
                self_ip='198.19.96.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.96.245',
                netmask='255.255.255.128'
            ),
            rules=['/Common/rule1', '/Common/rule2'],
            rules_egress=['/Common/rule_egress1', '/Common/rule_egress2'],
            devices=[dict(ip='198.19.96.30'), dict(ip='198.19.96.31')],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            snat_list=['198.19.64.10', '198.19.64.11'],
            proxy_type='transparent',
            auth_offload='no',
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080,
            default_persistence_profile='/Common/source_addr',
            service_entry_sslprofile='/Common/sslo-default-serverssl',
            service_return_sslprofile='/Common/sslo-default-clientssl'
        )

        p = ModuleParameters(params=args)
        assert p.devices == [{'ip': '198.19.96.30', 'port': 80}, {'ip': '198.19.96.31', 'port': 80}]
        assert p.devices_to == {
            'name': 'ssloN_proxy1a_in', 'path': '/Common/proxy1a-in-vlan', 'vlan': '/Common/proxy1a-in-vlan',
            'self_ip': '198.19.96.7', 'netmask': '255.255.255.128', 'network': '198.19.96.0'
        }
        assert p.devices_from == {
            'name': 'ssloN_proxy1a_out', 'path': '/Common/ssloN_proxy1a_out.app/ssloN_proxy1a_out',
            'interface': '1.1', 'tag': 50, 'self_ip': '198.19.96.245', 'netmask': '255.255.255.128',
            'network': '198.19.96.128'
        }
        assert p.name == 'ssloS_proxy1a'
        assert p.port_remap == 8080
        assert p.proxy_type == 'Transparent'
        assert p.snat == 'existingSNAT'
        assert p.snat_list == [{'ip': '198.19.64.10'}, {'ip': '198.19.64.11'}]
        assert p.rules == [
            {'name': '/Common/rule1', 'value': '/Common/rule1'},
            {'name': '/Common/rule2', 'value': '/Common/rule2'}
        ]
        assert p.rules_egress == [
            {'name': '/Common/rule_egress1', 'value': '/Common/rule_egress1'},
            {'name': '/Common/rule_egress2', 'value': '/Common/rule_egress2'}
        ]
        assert p.default_persistence_profile == '/Common/source_addr'
        assert p.service_entry_sslprofile == '/Common/sslo-default-serverssl'
        assert p.service_return_sslprofile == '/Common/sslo-default-clientssl'

    def test_api_parameters(self):
        args = load_fixture('return_sslo_http_params.json')
        p = ApiParameters(params=args)

        assert p.devices == [{'ip': '198.19.96.30', 'port': 80}, {'ip': '198.19.96.31', 'port': 80}]
        assert p.devices_from == {
            'name': 'ssloN_proxy1a_out', 'path': '/Common/ssloN_proxy1a_out.app/ssloN_proxy1a_out',
            'self_ip': '198.19.96.245',
            'netmask': '255.255.255.128', 'network': '198.19.96.128', 'interface': '1.1', 'tag': 50
        }
        assert p.devices_to == {
            'name': 'ssloN_proxy1a_in', 'path': '/Common/proxy1a-in-vlan', 'self_ip': '198.19.96.7',
            'netmask': '255.255.255.128', 'network': '198.19.96.0', 'vlan': '/Common/proxy1a-in-vlan'
        }
        assert p.monitor == '/Common/gateway_icmp'
        assert p.ip_family == 'ipv4'
        assert p.port_remap == 8080
        assert p.proxy_type == 'Transparent'
        assert p.service_down_action == 'reset'
        assert p.snat == 'existingSNAT'
        assert p.snat_pool == '/Common/proxy1a-snatpool'
        assert p.default_persistence_profile == '/Common/source_addr'
        assert p.service_entry_sslprofile == '/Common/sslo-default-serverssl'
        assert p.service_return_sslprofile == '/Common/sslo-default-clientssl'
        assert p.control_channels == []
        assert p.rules == ['/Common/test_ingress_rule']
        assert p.rules_egress == ['/Common/test_egress_rule']

    def test_devices_invalid_port_raises(self):
        p = ModuleParameters(params=dict(
            name='proxy1a', proxy_type='transparent', devices=[dict(ip='198.19.96.30', port=65536)]
        ))

        with self.assertRaisesRegex(F5ModuleError, '0 - 65535'):
            p.devices

    def test_explicit_proxy_device_without_port_raises(self):
        p = ModuleParameters(params=dict(
            name='proxy1a', proxy_type='explicit', devices=[dict(ip='198.19.96.30')]
        ))

        with self.assertRaisesRegex(F5ModuleError, 'Explicit proxy requires an IP and port'):
            p.devices

    def test_port_remap_with_explicit_proxy_raises(self):
        p = ModuleParameters(params=dict(name='proxy1a', proxy_type='explicit', port_remap=8080))

        with self.assertRaisesRegex(F5ModuleError, 'Port remap cannot be used'):
            p.port_remap

    def test_timeout_outside_supported_range_raises(self):
        for timeout in (9, 1801):
            p = ModuleParameters(params=dict(name='proxy1a', timeout=timeout))
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
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_http.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_http.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '7.5'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_http.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_http_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_http_create_generated.json')
        set_module_args(dict(
            name='proxy1a',
            devices_to=dict(
                vlan='/Common/proxy1a-in-vlan',
                self_ip='198.19.96.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.96.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.96.30'), dict(ip='198.19.96.31')],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            proxy_type='transparent',
            auth_offload=True,
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080,
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

    def test_create_http_service_object_dump_json_v14(self, *args):
        # Tests that version-gated fields (controlChannels >= 11.1, iRuleListEgress >= 13.0,
        # defaultPersistenceProfile >= 14.0) are included in the payload on sslo_version 14.0
        self.m3.return_value = '14.0'
        expected = load_fixture('sslo_http_create_v14_generated.json')
        set_module_args(dict(
            name='proxy1a',
            devices_to=dict(
                vlan='/Common/proxy1a-in-vlan',
                self_ip='198.19.96.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.96.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.96.30'), dict(ip='198.19.96.31')],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            proxy_type='transparent',
            auth_offload=True,
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080,
            rules=['/Common/test_ingress_rule'],
            rules_egress=['/Common/test_egress_rule'],
            default_persistence_profile='/Common/source_addr',
            service_entry_sslprofile='/Common/sslo-default-serverssl',
            service_return_sslprofile='/Common/sslo-default-clientssl',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['json'] == expected
        # Verify all version-gated fields are present in the payload
        custom_service = results['json']['inputProperties'][2]['value']['customService']
        assert 'controlChannels' in custom_service
        assert 'defaultPersistenceProfile' in custom_service
        assert custom_service['defaultPersistenceProfile'] == '/Common/source_addr'
        assert 'iRuleListEgress' in custom_service
        assert custom_service['iRuleListEgress'] == [
            {'name': '/Common/test_egress_rule', 'value': '/Common/test_egress_rule'}
        ]

    def test_modify_http_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_http_modify_generated.json')
        set_module_args(dict(
            name='proxy1a',
            devices=[dict(ip='10.10.100.100', port=3128), dict(ip='10.10.100.100', port=8080)],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_http_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_http_delete_generated.json')
        set_module_args(dict(
            name='proxy1a',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http2.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_http_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='proxy1a',
            devices_to=dict(
                vlan='/Common/proxy1a-in-vlan',
                self_ip='198.19.96.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.96.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.96.30'), dict(ip='198.19.96.31')],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            proxy_type='transparent',
            auth_offload='yes',
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_http_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_http_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['devices_to'] == {
            'vlan': '/Common/proxy1a-in-vlan', 'self_ip': '198.19.96.7', 'netmask': '255.255.255.128'
        }
        assert results['devices_from'] == {
            'interface': '1.1', 'tag': 50, 'self_ip': '198.19.96.245', 'netmask': '255.255.255.128'
        }
        assert results['devices'] == [{'ip': '198.19.96.30', 'port': 80}, {'ip': '198.19.96.31', 'port': 80}]
        assert results['ip_family'] == 'ipv4'
        assert results['service_down_action'] == 'reset'
        assert results['port_remap'] == 8080
        assert results['snat'] == 'snatpool'
        assert results['snat_pool'] == '/Common/proxy1a-snatpool'
        assert results['proxy_type'] == 'transparent'
        assert results['auth_offload'] == 'yes'

    def test_modify_http_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='proxy1a',
            snat='snatlist',
            snat_list=['198.19.64.10', '198.19.64.11'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_http_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_http_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['snat'] == 'snatlist'
        assert results['snat_list'] == ['198.19.64.10', '198.19.64.11']

    def test_delete_http_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='proxy1a',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http2.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_http_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_http_delete_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_version_check_raises_for_rules_egress_below_13(self, *args):
        # sslo_version mock returns '7.5' by default (< 13.0), so rules_egress must raise
        set_module_args(dict(
            name='proxy1a',
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
            name='proxy1a',
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

    def test_rules_reorder_detected_as_change(self, *args):
        # Verifies that reordering ingress iRules is treated as a real change,
        # because we use compare_complex_list_ordered instead of the unordered variant.
        self.m3.return_value = '9.0'
        set_module_args(dict(
            name='proxy1a',
            rules=['/Common/rule2', '/Common/rule1'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_http_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_http_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['rules'] == ['/Common/rule2', '/Common/rule1']

    # ------------------------------------------------------------------
    # Explicit proxy tests
    # ------------------------------------------------------------------

    def test_explicit_port_remap_raises(self, *args):
        # port_remap is not allowed with explicit proxy; the check fires
        # during payload building after required-params validation, so
        # we must supply the mandatory network/device args to reach it.
        set_module_args(dict(
            name='proxy1a',
            proxy_type='explicit',
            port_remap=8080,
            devices_to=dict(
                vlan='/Common/proxy1a-in-vlan',
                self_ip='198.19.96.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.96.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.96.30', port=3128)],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            ip_family='ipv4',
            service_down_action='reset',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaisesRegex(Exception, 'Port remap cannot be used with explicit proxy'):
            mm.exec_module()

    def test_create_explicit_http_service_object_dump_json_v14(self, *args):
        # Verifies that defaultPersistenceProfile, iRuleListEgress, and
        # controlChannels are all included in the explicit proxy payload at v14.
        self.m3.return_value = '14.0'
        expected = load_fixture('sslo_http_explicit_create_v14_generated.json')
        set_module_args(dict(
            name='proxy1a',
            devices_to=dict(
                vlan='/Common/proxy1a-in-vlan',
                self_ip='198.19.96.7',
                netmask='255.255.255.128'
            ),
            devices_from=dict(
                interface='1.1',
                tag=50,
                self_ip='198.19.96.245',
                netmask='255.255.255.128'
            ),
            devices=[dict(ip='198.19.96.30', port=3128)],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            proxy_type='explicit',
            auth_offload=True,
            ip_family='ipv4',
            service_down_action='reset',
            rules=['/Common/test_ingress_rule'],
            rules_egress=['/Common/test_egress_rule'],
            default_persistence_profile='/Common/source_addr',
            service_entry_sslprofile='/Common/sslo-default-serverssl',
            service_return_sslprofile='/Common/sslo-default-clientssl',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['json'] == expected
        custom_service = results['json']['inputProperties'][2]['value']['customService']
        assert custom_service['serviceSpecific']['proxyType'] == 'Explicit'
        assert custom_service['portRemap'] is False
        assert custom_service['defaultPersistenceProfile'] == '/Common/source_addr'
        assert 'iRuleListEgress' in custom_service
        assert custom_service['iRuleListEgress'] == [
            {'name': '/Common/test_egress_rule', 'value': '/Common/test_egress_rule'}
        ]

    def test_modify_explicit_http_with_rules_egress(self, *args):
        # Override version to 13.0 so rules_egress is accepted
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='proxy1a',
            rules_egress=['/Common/new_egress_rule'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http_explicit.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_http_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_http_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['rules_egress'] == ['/Common/new_egress_rule']

    def test_modify_explicit_http_with_default_persistence_profile(self, *args):
        # Override version to 14.0 so default_persistence_profile is accepted
        self.m3.return_value = '14.0'
        set_module_args(dict(
            name='proxy1a',
            default_persistence_profile='/Common/dest_addr',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_http_explicit.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_http_modify_done.json'))
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_http_modify_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['default_persistence_profile'] == '/Common/dest_addr'

    def test_api_parameters_explicit_proxy(self, *args):
        # Verifies ApiParameters reads explicit proxy fields correctly
        args = load_fixture('load_sslo_service_http_explicit.json')
        p = ApiParameters(params=args['items'][0]['inputProperties'][0]['value'])
        assert p.proxy_type == 'Explicit'
        assert p.port_remap is None
        assert p.default_persistence_profile == '/Common/source_addr'
        assert p.rules == ['/Common/test_ingress_rule']
        assert p.rules_egress == ['/Common/test_egress_rule']
        assert p.control_channels == []

    def test_update_idempotent(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.want = Mock(dump_json=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()

    def test_immutable_networks_and_vendor_info_raise(self):
        want = Mock(
            devices_to={'name': 'toNetwork', 'self_ip': '198.19.96.8', 'netmask': '255.255.255.128'},
            devices_from={'name': 'fromNetwork', 'self_ip': '198.19.96.246', 'netmask': '255.255.255.128'},
            use_exist_selfip=False,
            vendor_info='New vendor'
        )
        have = Mock(
            devices_to={'name': 'toNetwork', 'self_ip': '198.19.96.7', 'netmask': '255.255.255.128'},
            devices_from={'name': 'fromNetwork', 'self_ip': '198.19.96.245', 'netmask': '255.255.255.128'},
            vendor_info='Generic HTTP Service'
        )
        diff = Difference(want, have)

        with self.assertRaisesRegex(F5ModuleError, 'Self-IPs are immutable'):
            diff.devices_to
        with self.assertRaisesRegex(F5ModuleError, 'Self-IPs are immutable'):
            diff.devices_from
        with self.assertRaisesRegex(F5ModuleError, 'vendor'):
            diff.vendor_info

    def test_unsupported_sslo_version_raises(self):
        self.m3.return_value = '7.0'
        set_module_args(dict(name='proxy1a'))
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
        manager.want = Mock(name='ssloS_proxy1a')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='exists failed')))

        with self.assertRaisesRegex(F5ModuleError, 'exists failed'):
            manager.exists()

    def test_create_update_and_remove_errors_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.version = '14.0'
        manager.want = Mock(dump_json=False)
        manager.changes = Mock(to_return=Mock(return_value={}))
        manager.removals = Mock(to_return=Mock(return_value={}))
        manager.add_json_metadata = Mock(side_effect=lambda payload: payload)
        manager.add_create_values = Mock(side_effect=lambda payload: payload)
        manager.add_missing_options = Mock(side_effect=lambda payload: payload)
        manager.client = Mock(post=Mock(return_value=dict(code=500, contents='operation failed')))

        with patch.object(bigip_sslo_service_http, 'process_json', return_value={}):
            for operation in (manager.create_on_device, manager.update_on_device, manager.remove_from_device):
                with self.assertRaisesRegex(F5ModuleError, 'operation failed'):
                    operation()

    def test_read_current_error_and_missing_item_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='ssloS_proxy1a')
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
        with patch.object(bigip_sslo_service_http, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_http, 'Connection'), \
                patch.object(bigip_sslo_service_http, 'HAS_NETADDR', True), \
                patch.object(bigip_sslo_service_http, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_http, 'ModuleManager', return_value=manager):
            bigip_sslo_service_http.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('service failed')
        with patch.object(bigip_sslo_service_http, 'AnsibleModule', return_value=module), \
                patch.object(bigip_sslo_service_http, 'Connection'), \
                patch.object(bigip_sslo_service_http, 'HAS_NETADDR', True), \
                patch.object(bigip_sslo_service_http, 'HAS_PACKAGING', True), \
                patch.object(bigip_sslo_service_http, 'ModuleManager', return_value=manager):
            bigip_sslo_service_http.main()

        module.fail_json.assert_called_once_with(msg='service failed')
