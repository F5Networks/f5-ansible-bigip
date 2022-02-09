# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain import (
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
            name="demo_chain_1",
            services=[
                dict(service_name="icap1", type="icap", ip_family="ipv4"),
                dict(service_name="layer3a", type="L3")
            ]
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloSC_demo_chain_1'
        assert p.services == [{'name': 'ssloS_icap1', 'ipFamily': 'ipv4', 'serviceType': 'icap'},
                              {'name': 'ssloS_layer3a', 'ipFamily': 'ipv4', 'serviceType': 'L3'}]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_service_chain_params.json')

        p = ApiParameters(params=args)
        assert p.name == 'ssloSC_demo_chain_1'
        assert p.services == [{'name': 'ssloS_icap1', 'ipFamily': 'ipv4', 'serviceType': 'icap'},
                              {'name': 'ssloS_layer3a', 'ipFamily': 'ipv4', 'serviceType': 'L3'}]


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_service_chain.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_service_chain_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_sc_create_generated.json')
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="icap1", type="icap", ip_family="ipv4")
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_service_chain_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_sc_modify_generated.json')
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="layer3a", type="L3", ip_family="ipv4")
            ],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_service_chain_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_sc_delete_generated.json')
        set_module_args(dict(
            name='foobar',
            dump_json=True,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sslo_sc.json')))

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_service_chain_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="icap1", type="icap", ip_family="ipv4")
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_create_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('reply_sslo_sc_create_done.json')))

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['services'] == [{'name': 'ssloS_icap1', 'ipFamily': 'ipv4', 'serviceType': 'icap'}]

    def test_modify_service_chain_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name="foobar",
            services=[
                dict(service_name="layer3a", type="L3", ip_family="ipv4")
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_sc_modify_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_modify_start.json')))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['services'] == [{'name': 'ssloS_layer3a', 'ipFamily': 'ipv4', 'serviceType': 'L3'}]

    def test_delete_service_chain_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='foobar',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_sc.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_sc_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_sc_delete_start.json')))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
