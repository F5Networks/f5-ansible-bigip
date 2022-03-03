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
        self.m3.return_value = '8.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    # def test_create_layer3_service_object_dump_json(self, *args):
    #     # Configure the arguments that would be sent to the Ansible module
    #     expected = load_fixture('sslo_layer3_create_generated.json')
    #     set_module_args(dict(
    #         name="layer3a",
    #         devices_to=dict(
    #             interface='1.1',
    #             tag=40,
    #             self_ip='198.19.64.7',
    #             netmask='255.255.255.128'
    #         ),
    #         devices_from=dict(
    #             interface='1.1',
    #             tag=50,
    #             self_ip='198.19.64.245',
    #             netmask='255.255.255.128'
    #         ),
    #         devices=[dict(ip='198.19.64.30'), dict(ip='198.19.64.31')],
    #         service_down_action='ignore',
    #         port_remap=8081,
    #         dump_json=True
    #     ))
    #
    #     module = AnsibleModule(
    #         argument_spec=self.spec.argument_spec,
    #         supports_check_mode=self.spec.supports_check_mode,
    #     )
    #     mm = ModuleManager(module=module)
    #
    #     # Override methods to force specific logic in the module to happen
    #     mm.exists = Mock(return_value=False)
    #
    #     results = mm.exec_module()
    #
    #     assert results['changed'] is False
    #     assert results['json'] == expected

    # def test_modify_layer3_service_object_dump_json(self, *args):
    #     # Configure the arguments that would be sent to the Ansible module
    #     expected = load_fixture('sslo_layer3_modify_generated.json')
    #     set_module_args(dict(
    #         name="layer3a",
    #         snat='snatlist',
    #         snat_list=['198.19.64.10', '198.19.64.11', '198.19.64.12'],
    #         dump_json=True
    #     ))
    #
    #     module = AnsibleModule(
    #         argument_spec=self.spec.argument_spec,
    #         supports_check_mode=self.spec.supports_check_mode,
    #     )
    #     mm = ModuleManager(module=module)
    #
    #     exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
    #     # Override methods to force specific logic in the module to happen
    #     mm.client.get = Mock(side_effect=[exists, exists])
    #
    #     results = mm.exec_module()
    #
    #     assert results['changed'] is True
    #     assert results['json'] == expected

    # def test_modify_layer3_service_object(self, *args):
    #     # Configure the arguments that would be sent to the Ansible module
    #     set_module_args(dict(
    #         name="layer3a",
    #         snat='snatlist',
    #         snat_list=['198.19.64.10', '198.19.64.11', '198.19.64.12'],
    #     ))
    #
    #     module = AnsibleModule(
    #         argument_spec=self.spec.argument_spec,
    #         supports_check_mode=self.spec.supports_check_mode,
    #     )
    #     mm = ModuleManager(module=module)
    #
    #     exists = dict(code=200, contents=load_fixture('load_sslo_service_layer3.json'))
    #     done = dict(code=200, contents=load_fixture('reply_sslo_layer3_modify_done.json'))
    #     # Override methods to force specific logic in the module to happen
    #     mm.client.post = Mock(return_value=dict(
    #         code=202, contents=load_fixture('reply_sslo_layer3_modify_start.json')
    #     ))
    #     mm.client.get = Mock(side_effect=[exists, exists, done])
    #
    #     results = mm.exec_module()
    #     assert results['changed'] is True
    #     assert results['snat'] == 'snatlist'
    #     assert results['snat_list'] == ['198.19.64.10', '198.19.64.11', '198.19.64.12']

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
