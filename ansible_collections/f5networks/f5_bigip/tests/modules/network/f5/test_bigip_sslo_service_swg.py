# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg import (
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
            name='barfoo',
            swg_policy='/Common/swg_baz',
            profile_scope='profile',
            named_scope='INVALID',
            access_profile='/Common/bazbar',
            service_down_action='ignore',
            log_settings=['/Common/log1', '/Common/log2'],
            rules=['/Common/rule1', '/Common/rule2']
        )

        p = ModuleParameters(params=args)
        assert p.name == 'ssloS_barfoo'
        assert p.swg_policy == '/Common/swg_baz'
        assert p.profile_scope == 'profile'
        assert p.access_profile == '/Common/bazbar'
        assert p.service_down_action == 'ignore'
        assert p.named_scope == 'INVALID'
        assert p.log_settings == [
            {'name': '/Common/log1', 'value': '/Common/log1'}, {'name': '/Common/log2', 'value': '/Common/log2'}
        ]
        assert p.rules == [
            {'name': '/Common/ssloS_barfoo.app/ssloS_barfoo-swg',
             'value': '/Common/ssloS_barfoo.app/ssloS_barfoo-swg'},
            {'name': '/Common/rule1', 'value': '/Common/rule1'},
            {'name': '/Common/rule2', 'value': '/Common/rule2'}
        ]

    def test_api_parameters(self):
        args = load_fixture('return_sslo_swg_service_params.json')

        p = ApiParameters(params=args)

        assert p.named_scope == ''
        assert p.access_profile == '/Common/ssloS_swg_default.app/ssloS_swg_default_M_accessProfile'
        assert p.profile_scope == 'profile'
        assert p.service_down_action == 'reset'
        assert p.swg_policy == '/Common/test-swg'
        assert p.log_settings == [{'name': '/Common/default-log-setting', 'value': '/Common/default-log-setting'}]
        assert p.rules == [
            {'name': '/Common/ssloS_swg_default.app/ssloS_swg_default-swg',
             'value': '/Common/ssloS_swg_default.app/ssloS_swg_default-swg'}
        ]


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = '9.0'

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_swg_service_object_with_defaults_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_swg_create_defaults_generated.json')
        set_module_args(dict(
            name='swg_default',
            swg_policy='/Common/test-swg',
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

    def test_create_swg_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_swg_create_generated.json')
        set_module_args(dict(
            name='swg_custom',
            swg_policy='/Common/test-swg',
            access_profile='/Common/test_access2',
            named_scope='SSLO',
            profile_scope='named',
            rules=['/Common/test_rule_1', '/Common/test_rule_2'],
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

    def test_modify_swg_service_object_defaults_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_swg_modify_defaults_generated.json')
        set_module_args(dict(
            name='swg_default',
            rules=['/Common/test_rule_1', '/Common/test_rule_2'],
            access_profile='/Common/test_access1',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg_default.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_modify_swg_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_swg_modify_generated.json')
        set_module_args(dict(
            name='swg_custom',
            rules=['/Common/test_rule_1'],
            access_profile='/Common/test_access1',
            named_scope='',
            profile_scope='profile',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(side_effect=[exists, exists])

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_delete_swg_service_object_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_swg_delete_generated.json')
        set_module_args(dict(
            name='swg_custom',
            state='absent',
            dump_json=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.get = Mock(return_value=exists)

        results = mm.exec_module()

        assert results['changed'] is False
        assert results['json'] == expected

    def test_create_swg_service_object_with_defaults(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='swg_default',
            swg_policy='/Common/test-swg'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_swg_create_defaults_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_swg_create_defaults_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['swg_policy'] == '/Common/test-swg'

    def test_create_swg_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='swg_custom',
            swg_policy='/Common/test-swg',
            access_profile='/Common/test_access2',
            named_scope='SSLO',
            profile_scope='named',
            rules=['/Common/test_rule_1', '/Common/test_rule_2'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_swg_create_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_swg_create_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['swg_policy'] == '/Common/test-swg'
        assert results['access_profile'] == '/Common/test_access2'
        assert results['named_scope'] == 'SSLO'
        assert results['profile_scope'] == 'named'
        assert results['rules'] == [
            {'name': '/Common/ssloS_swg_custom.app/ssloS_swg_custom-swg',
             'value': '/Common/ssloS_swg_custom.app/ssloS_swg_custom-swg'},
            {'name': '/Common/test_rule_1', 'value': '/Common/test_rule_1'},
            {'name': '/Common/test_rule_2', 'value': '/Common/test_rule_2'}
        ]

    def test_modify_swg_service_object_defaults(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='swg_default',
            rules=['/Common/test_rule_1', '/Common/test_rule_2'],
            access_profile='/Common/test_access1'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg_default.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_swg_modify_defaults_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_swg_modify_defaults_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['access_profile'] == '/Common/test_access1'
        assert results['rules'] == [
            {'name': '/Common/ssloS_swg_default.app/ssloS_swg_default-swg',
             'value': '/Common/ssloS_swg_default.app/ssloS_swg_default-swg'},
            {'name': '/Common/test_rule_1', 'value': '/Common/test_rule_1'},
            {'name': '/Common/test_rule_2', 'value': '/Common/test_rule_2'}
        ]

    def test_modify_swg_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='swg_custom',
            rules=['/Common/test_rule_1'],
            access_profile='/Common/test_access1',
            named_scope='',
            profile_scope='profile',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_swg_modify_defaults_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_swg_modify_defaults_start.json')
        ))
        mm.client.get = Mock(side_effect=[exists, exists, done])

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['named_scope'] == ''
        assert results['profile_scope'] == 'profile'
        assert results['access_profile'] == '/Common/test_access1'
        assert results['rules'] == [
            {'name': '/Common/ssloS_swg_custom.app/ssloS_swg_custom-swg',
             'value': '/Common/ssloS_swg_custom.app/ssloS_swg_custom-swg'},
            {'name': '/Common/test_rule_1', 'value': '/Common/test_rule_1'}
        ]

    def test_delete_swg_service_object(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='swg_custom',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg.json'))
        done = dict(code=200, contents=load_fixture('reply_sslo_swg_delete_done.json'))
        # Override methods to force specific logic in the module to happen
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('reply_sslo_swg_delete_start.json')))
        mm.client.get = Mock(side_effect=[exists, done])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_create_swg_object_missing_swg_policy(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        err = 'The swg_policy parameter is not defined. ' \
              'Existing SWG per-request policy must be defined for CREATE operation.'
        set_module_args(dict(
            name='foobar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,

        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert str(res.exception) == err
