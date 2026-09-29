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
            swg_policy_type='standard',
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
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_create_swg_service_object_with_defaults_dump_json(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        expected = load_fixture('sslo_swg_create_defaults_generated.json')
        set_module_args(dict(
            name='swg_default',
            swg_policy='/Common/test-swg',
            swg_policy_type='modern',
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
            swg_policy_type='modern',
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
            swg_policy_type='modern',
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
            swg_policy_type='modern',
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
            swg_policy_type="standard",
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
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
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
            swg_policy_type='standard',
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
            swg_policy_type="standard",
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
            swg_policy_type="standard",
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
            swg_policy_type="standard",
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
        err1 = 'missing required arguments: swg_policy_type'
        set_module_args(dict(
            name='foobar',
            swg_policy_type="standard"
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

    def test_timeout_validation_too_low(self, *args):
        # Test timeout below minimum (< 10)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard',
            timeout=9
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents={'id': 'task-123'}
        ))
        # timeout validation happens when wait_for_task accesses it
        mm._check_task_on_device = Mock(return_value={
            'id': 'task-123',
            'state': 'PENDING'
        })

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Timeout value must be between 10 and 1800' in str(res.exception)

    def test_timeout_validation_too_high(self, *args):
        # Test timeout above maximum (> 1800)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard',
            timeout=1801
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents={'id': 'task-123'}
        ))
        # timeout validation happens when wait_for_task accesses it
        mm._check_task_on_device = Mock(return_value={
            'id': 'task-123',
            'state': 'PENDING'
        })

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Timeout value must be between 10 and 1800' in str(res.exception)

    def test_version_check_below_minimum(self, *args):
        # Test SSLO version below minimum (< 9.0)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        # Patch sslo_version to return version below minimum
        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.sslo_version') as m:
            m.return_value = '8.9'
            with self.assertRaises(F5ModuleError) as res:
                mm.exec_module()
            assert 'Unsupported SSL Orchestrator version' in str(res.exception)

    def test_version_check_above_maximum(self, *args):
        # Test SSLO version above maximum (> 12.0)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        # Patch sslo_version to return version above maximum
        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.sslo_version') as m:
            m.return_value = '12.1'
            with self.assertRaises(F5ModuleError) as res:
                mm.exec_module()
            assert 'Unsupported SSL Orchestrator version' in str(res.exception)

    def test_exists_http_error_response(self, *args):
        # Test exists() method with HTTP error response
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=400, contents='Bad Request'))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Bad Request' in str(res.exception)

    def test_create_http_error_response(self, *args):
        # Test create_on_device() with HTTP error response
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=400, contents='Create failed'))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Create failed' in str(res.exception)

    def test_update_http_error_response(self, *args):
        # Test update_on_device() with HTTP error response
        set_module_args(dict(
            name='swg_default',
            swg_policy_type='standard',
            service_down_action='ignore'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg_default.json'))
        mm.client.get = Mock(side_effect=[exists, exists])
        mm.client.post = Mock(return_value=dict(code=400, contents='Update failed'))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Update failed' in str(res.exception)

    def test_remove_http_error_response(self, *args):
        # Test remove_from_device() with HTTP error response
        set_module_args(dict(
            name='swg_custom',
            swg_policy_type='standard',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg.json'))
        mm.client.get = Mock(return_value=exists)
        mm.client.post = Mock(return_value=dict(code=400, contents='Delete failed'))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Delete failed' in str(res.exception)

    def test_read_current_from_device_http_error(self, *args):
        # Test read_current_from_device() with HTTP error response
        set_module_args(dict(
            name='test_service',
            swg_policy_type='standard',
            service_down_action='ignore'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        # First exists() call returns success, but read_current gets error
        exists = dict(code=200, contents={'items': [{'id': 'test-id', 'name': 'ssloS_test_service'}]})
        error_resp = dict(code=400, contents='Read failed')
        mm.client.get = Mock(side_effect=[exists, error_resp])

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Read failed' in str(res.exception)

    def test_wait_for_task_error_state(self, *args):
        # Test wait_for_task() when task reaches ERROR state
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents={'id': 'task-123'}
        ))
        # Mock _check_task_on_device to return ERROR state
        mm._check_task_on_device = Mock(return_value={
            'id': 'task-123',
            'state': 'ERROR',
            'error': 'Task execution failed'
        })

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'CREATE operation error' in str(res.exception)
        assert 'Task execution failed' in str(res.exception)

    def test_wait_for_task_timeout(self, *args):
        # Test wait_for_task() when module timeout is reached
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard',
            timeout=10  # Minimal timeout = 1 second per iteration
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents={'id': 'task-123'}
        ))
        # Mock _check_task_on_device to always return PENDING state
        mm._check_task_on_device = Mock(return_value={
            'id': 'task-123',
            'state': 'PENDING'
        })

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Module timeout reached' in str(res.exception)

    def test_check_task_on_device_http_error(self, *args):
        # Test _check_task_on_device() with HTTP error response
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard',
            timeout=10
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents={'id': 'task-123'}
        ))
        # Mock client.get to return error for task check
        mm.client.get = Mock(return_value=dict(
            code=500, contents='Internal Server Error'
        ))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Internal Server Error' in str(res.exception)

    def test_idempotent_modify_no_changes(self, *args):
        # Test modify when no actual changes are needed (idempotent)
        set_module_args(dict(
            name='swg_default',
            swg_policy_type='standard',
            service_down_action='reset'  # Same as existing, no change
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        # Load existing service state
        existing = {
            'customService': {
                'serviceSpecific': {
                    'perReqPolicy': '/Common/test-swg',
                    'accessProfileScopeCustSource': '/Common/standard',
                    'accessProfileScope': 'profile',
                    'accessProfileNameScopeValue': '',
                    'accessProfile': '/Common/ssloS_swg_default.app/ssloS_swg_default_S_accessProfile',
                    'logSettings': [{'name': '/Common/default-log-setting', 'value': '/Common/default-log-setting'}],
                    'iRuleList': [
                        {
                            'name': '/Common/ssloS_swg_default.app/ssloS_swg_default-swg',
                            'value': '/Common/ssloS_swg_default.app/ssloS_swg_default-swg'
                        }
                    ]
                },
                'serviceDownAction': 'reset'
            }
        }
        exists = dict(code=200, contents={'items': [{'id': 'test-id', 'name': 'ssloS_swg_default', 'inputProperties': [{'value': existing}]}]})
        mm.client.get = Mock(return_value=exists)

        results = mm.exec_module()

        assert results['changed'] is False

    def test_idempotent_absent_when_not_exists(self, *args):
        # Test absent state when service doesn't exist (idempotent)
        set_module_args(dict(
            name='nonexistent_service',
            swg_policy_type='standard',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents={'items': []}))

        results = mm.exec_module()

        assert results['changed'] is False

    def test_check_mode_create(self, *args):
        # Test create in check mode (no actual changes)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        module.check_mode = True
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.post.assert_not_called()

    def test_check_mode_modify(self, *args):
        # Test modify in check mode (no actual changes)
        set_module_args(dict(
            name='swg_default',
            swg_policy_type='standard',
            service_down_action='ignore'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        module.check_mode = True
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg_default.json'))
        mm.client.get = Mock(return_value=exists)

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.post.assert_not_called()

    def test_check_mode_absent(self, *args):
        # Test absent in check mode (no actual changes)
        set_module_args(dict(
            name='swg_custom',
            swg_policy_type='standard',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        module.check_mode = True
        mm = ModuleManager(module=module)
        exists = dict(code=200, contents=load_fixture('load_sslo_service_swg.json'))
        mm.client.get = Mock(return_value=exists)

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.post.assert_not_called()

    def test_timeout_edge_case_lower_bound(self, *args):
        # Test timeout at lower boundary (exactly 10 seconds)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard',
            timeout=10
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_swg_create_defaults_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_swg_create_defaults_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True

    def test_timeout_edge_case_upper_bound(self, *args):
        # Test timeout at upper boundary (exactly 1800 seconds)
        set_module_args(dict(
            name='test_service',
            swg_policy='/Common/test-swg',
            swg_policy_type='standard',
            timeout=1800
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('reply_sslo_swg_create_defaults_start.json'))
        )
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('reply_sslo_swg_create_defaults_done.json'))
        )

        results = mm.exec_module()

        assert results['changed'] is True


class TestMainFunction(unittest.TestCase):
    def setUp(self):
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.AnsibleModule')
        self.m2 = self.p2.start()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.ModuleManager')
        self.m3 = self.p3.start()
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg.Connection')
        self.m4 = self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_main_function_success(self, *args):
        # Test main() function with successful module execution
        from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg import main

        module_instance = MagicMock()
        manager_instance = MagicMock()
        manager_instance.exec_module.return_value = {'changed': True, 'name': 'test_service'}

        self.m2.return_value = module_instance
        self.m3.return_value = manager_instance

        with patch.object(module_instance, 'exit_json') as mock_exit:
            main()
            mock_exit.assert_called_once()
            call_args = mock_exit.call_args[1]
            assert call_args['changed'] is True

    def test_main_function_f5_module_error(self, *args):
        # Test main() function when F5ModuleError is raised
        from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_service_swg import main

        module_instance = MagicMock()
        manager_instance = MagicMock()
        manager_instance.exec_module.side_effect = F5ModuleError('Test error message')

        self.m2.return_value = module_instance
        self.m3.return_value = manager_instance

        with patch.object(module_instance, 'fail_json') as mock_fail:
            main()
            mock_fail.assert_called_once()
            call_args = mock_fail.call_args[1]
            assert 'Test error message' in call_args['msg']

    def test_update_swg_idempotent(self, *args):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()
        manager.should_update.assert_called_once()
