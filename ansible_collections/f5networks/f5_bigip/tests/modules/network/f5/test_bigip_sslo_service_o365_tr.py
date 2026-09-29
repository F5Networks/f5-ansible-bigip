# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_o365_tr import (
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


def get_fixture_data(filename, key=None):
    """Load fixture file and optionally extract a specific key from it"""
    data = load_fixture(filename)
    if key and isinstance(data, dict):
        return data.get(key, data)
    return data


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            name='o365_test',
            restrict_access_to_tenant='example_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=['/Common/test_rule_1', '/Common/test_rule_2']
        )
        p = ModuleParameters(params=args)
        assert p.name == 'ssloS_o365_test'
        assert p.restrict_access_to_tenant == 'example_tenant'
        assert p.restrict_access_context == 'Generic o365 tenant restrictions Service'
        assert p.rules == [
            {'name': '/Common/test_rule_1', 'value': '/Common/test_rule_1'},
            {'name': '/Common/test_rule_2', 'value': '/Common/test_rule_2'}
        ]
        assert p.sub_type == 'o365'

    def test_module_parameters_defaults(self):
        args = dict(name='o365_test')
        p = ModuleParameters(params=args)
        assert p.name == 'ssloS_o365_test'
        assert p.restrict_access_context == 'Generic o365 tenant restrictions Service'
        assert p.rules == []
        assert p.sub_type == 'o365'

    def test_module_parameters_empty_irule_list(self):
        args = dict(
            name='o365_test',
            restrict_access_to_tenant='tenant1',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=[]
        )
        p = ModuleParameters(params=args)
        assert p.rules == []

    def test_api_parameters(self):
        args = load_fixture('return_sslo_o365_tr_params.json')
        p = ApiParameters(params=args)
        assert p.restrict_access_to_tenant == 'company_tenant'
        assert p.restrict_access_context == 'Generic o365 tenant restrictions Service'
        # System-added iRule should be filtered out
        assert len(p.rules) == 2
        assert p.rules[0]['name'] == '/Common/test_rule_1'
        assert p.rules[1]['name'] == '/Common/test_rule_2'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_o365_tr.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_o365_tr.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '7.5'
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_o365_tr.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_o365_tr_service_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = get_fixture_data('sslo_o365_tr_create_payloads.json', 'with_irules')
        set_module_args(dict(
            name='o365_tr1',
            restrict_access_to_tenant='example_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=['/Common/test_rule_1'],
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

    def test_create_o365_tr_service_no_irules_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = get_fixture_data('sslo_o365_tr_create_payloads.json', 'no_irules')
        set_module_args(dict(
            name='o365_tr_empty',
            restrict_access_to_tenant='test_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=[],
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

    def test_modify_o365_tr_service_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_o365_tr_modify_generated.json')
        set_module_args(dict(
            name='o365_tr1',
            restrict_access_to_tenant='modified_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=['/Common/test_rule_1', '/Common/test_rule_3'],
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=get_fixture_data('load_sslo_o365_tr_states.json', 'current_state'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_o365_tr_service_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_o365_tr_delete_generated.json')
        set_module_args(dict(
            name='o365_tr1',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=get_fixture_data('load_sslo_o365_tr_states.json', 'modified_state'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_o365_tr_service(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='o365_tr1',
            restrict_access_to_tenant='example_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=['/Common/test_rule_1']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'create_start'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'create_done'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['restrict_access_to_tenant'] == 'example_tenant'
        assert results['restrict_access_context'] == 'Generic o365 tenant restrictions Service'

    def test_create_o365_tr_service_no_irules(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='o365_tr_empty',
            restrict_access_to_tenant='test_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=[]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'create_start'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'create_done_no_irules'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['rules'] == []

    def test_modify_o365_tr_service(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='o365_tr1',
            restrict_access_to_tenant='modified_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=['/Common/test_rule_1', '/Common/test_rule_3']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=get_fixture_data('load_sslo_o365_tr_states.json', 'current_state'))
        done = dict(code=200, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'modify_done'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'modify_start')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['restrict_access_to_tenant'] == 'modified_tenant'

    def test_delete_o365_tr_service(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='o365_tr1',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=get_fixture_data('load_sslo_o365_tr_states.json', 'current_state'))
        done = dict(code=200, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'delete_done'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=get_fixture_data('reply_sslo_o365_tr_responses.json', 'delete_start')
        ))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_idempotent_check_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='o365_tr1',
            restrict_access_to_tenant='example_tenant',
            restrict_access_context='Generic o365 tenant restrictions Service',
            rules=['/Common/test_rule_1', '/Common/test_rule_2']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=get_fixture_data('load_sslo_o365_tr_states.json', 'current_state'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()
        assert results['changed'] is False
