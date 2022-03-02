# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap import (
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
            name='tap_test',
            devices=dict(
                interface='1.1',
                tag=400
            ),
            mac_address='fa:15:4e:a2:43:a8',
            port_remap=80
        )
        p = ModuleParameters(params=args)
        assert p.devices == {
            'name': 'ssloN_tap_test', 'interface': '1.1', 'path': '/Common/ssloN_tap_test.app/ssloN_tap_test',
            'tag': 400, 'ipv4_deviceip': '198.19.182.10', 'ipv4_haselfip': '198.19.182.9',
            'ipv4_selfip': '198.19.182.8', 'ipv4_subnet': '198.19.182.0', 'ipv6_deviceip': '2001:200:0:ca9a::a',
            'ipv6_haselfip': '2001:200:0:ca9a::9', 'ipv6_selfip': '2001:200:0:ca9a::8', 'ipv6_subnet': '2001:200:0:ca9a::'
        }
        assert p.mac_address == 'fa:15:4e:a2:43:a8'
        assert p.port_remap == 80

    def test_api_parameters(self):
        args = load_fixture('return_sslo_tap_params.json')
        p = ApiParameters(params=args)

        assert p.devices == {
            'name': 'ssloN_tap_test', 'interface': '1.1', 'path': '/Common/ssloN_tap_test.app/ssloN_tap_test',
            'tag': 400, 'ipv4_deviceip': '198.19.182.10', 'ipv4_haselfip': '198.19.182.9',
            'ipv4_selfip': '198.19.182.8', 'ipv4_subnet': '198.19.182.0', 'ipv6_deviceip': '2001:200:0:ca9a::a',
            'ipv6_haselfip': '2001:200:0:ca9a::9', 'ipv6_selfip': '2001:200:0:ca9a::8',
            'ipv6_subnet': '2001:200:0:ca9a::'
        }

        assert p.port_remap == 80
        assert p.service_down_action == 'ignore'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_tap.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '8.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    # def test_create_tap_service_object_dump_json(self, *args):
    #     # Configure the arguments that would be sent to the Ansible module
    #     expected = load_fixture('sslo_tap_create_generated.json')
    #
    #     set_module_args(dict(
    #         name='tap_test',
    #         devices=dict(
    #             interface='1.1',
    #             tag=400
    #         ),
    #         mac_address='fa:16:3e:a1:42:a8',
    #         dump_json=True
    #     ))
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
    #
    # def test_modify_tap_service_object_dump_json(self, *args):
    #     # Configure the arguments that would be sent to the Ansible module
    #     expected = load_fixture('sslo_tap_modify_generated.json')
    #     set_module_args(dict(
    #         name='tap_test',
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
    #     exists = dict(code=200, contents=load_fixture('load_sslo_service_tap.json'))
    #     # Override methods to force specific logic in the module to happen
    #     mm.client.get = Mock(side_effect=[exists, exists])
    #
    #     results = mm.exec_module()
    #
    #     assert results['changed'] is False
    #     assert results['json'] == expected

    def test_create_tap_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='tap_test',
            devices=dict(
                interface='1.1',
                tag=400
            ),
            mac_address='fa:16:3e:a1:42:a8',
            port_remap=8080
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_tap_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_tap_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['port_remap'] == 8080
        assert results['devices'] == {
            'name': 'ssloN_tap_test', 'interface': '1.1', 'path': '/Common/ssloN_tap_test.app/ssloN_tap_test',
            'tag': 400, 'ipv4_deviceip': '198.19.182.10', 'ipv4_haselfip': '198.19.182.9',
            'ipv4_selfip': '198.19.182.8', 'ipv4_subnet': '198.19.182.0', 'ipv6_deviceip': '2001:200:0:ca9a::a',
            'ipv6_haselfip': '2001:200:0:ca9a::9', 'ipv6_selfip': '2001:200:0:ca9a::8',
            'ipv6_subnet': '2001:200:0:ca9a::'
        }

    # def test_modify_tap_service_object(self, *args):
    #     # Configure the arguments that would be sent to the Ansible module
    #     set_module_args(dict(
    #         name='proxy1a',
    #         snat='snatlist',
    #         snat_list=['198.19.64.10', '198.19.64.11'],
    #     ))
    #
    #     module = AnsibleModule(
    #         argument_spec=self.spec.argument_spec,
    #         supports_check_mode=self.spec.supports_check_mode,
    #     )
    #     mm = ModuleManager(module=module)
    #
    #     exists = dict(code=200, contents=load_fixture('load_sslo_service_tap.json'))
    #     done = dict(code=200, contents=load_fixture('reply_sslo_tap_modify_done.json'))
    #     # Override methods to force specific logic in the module to happen
    #     mm.client.post = Mock(return_value=dict(
    #         code=202, contents=load_fixture('reply_sslo_tap_modify_start.json')
    #     ))
    #     mm.client.get = Mock(side_effect=[exists, exists, done])
    #
    #     results = mm.exec_module()
    #     assert results['changed'] is True
    #     assert results['snat'] == 'snatlist'
    #     assert results['snat_list'] == ['198.19.64.10', '198.19.64.11']
