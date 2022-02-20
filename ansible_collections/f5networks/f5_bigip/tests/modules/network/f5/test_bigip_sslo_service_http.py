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
            devices=[dict(ip='198.19.96.30'), dict(ip='198.19.96.31')],
            snat='snatpool',
            snat_pool='/Common/proxy1a-snatpool',
            snat_list=['198.19.64.10', '198.19.64.11'],
            proxy_type='transparent',
            auth_offload='no',
            ip_family='ipv4',
            service_down_action='reset',
            port_remap=8080
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

    def test_api_parameters(self):
        args = load_fixture('return_sslo_http_params.json')
        p = ApiParameters(params=args)

        assert p.devices == [{'ip': '198.19.96.30', 'port': 80}, {'ip': '198.19.96.31', 'port': 80}]
        assert p.devices_from == {
            'name': 'ssloN_proxy1a_out', 'path': '/Common/proxy1a-in-vlan', 'self_ip': '198.19.96.245',
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

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

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

    def test_modify_http_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_http_modify_generated.json')
        set_module_args(dict(
            name='proxy1a',
            snat='snatlist',
            snat_list=['198.19.64.10', '198.19.64.11'],
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
