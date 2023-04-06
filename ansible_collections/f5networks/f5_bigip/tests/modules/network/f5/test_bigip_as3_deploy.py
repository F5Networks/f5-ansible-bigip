# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_as3_deploy
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_as3_deploy import (
    Parameters, ArgumentSpec, ModuleManager, ModuleParameters
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, AnsibleFailJson, AnsibleExitJson, fail_json, exit_json
)


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
            content=dict(param1='foo', param2='bar'),
            tenant='test_tenant',
            timeout=600,
        )
        p = Parameters(params=args)
        self.assertEqual(p.content, dict(param1='foo', param2='bar'))
        self.assertEqual(p.timeout, 600)

    def test_module_parameters_content(self):
        args1 = dict(
            content='{"param1":"foo", "param2":"bar"}'
        )
        p1 = ModuleParameters(params=args1)
        args2 = dict()
        p2 = ModuleParameters(params=args2)
        self.assertEqual(p1.content, dict(param1='foo', param2='bar'))
        self.assertEqual(p2.content, None)

    def test_module_parameters_timeout(self):
        args1 = dict(
            timeout=9
        )
        args2 = dict(
            timeout=1801
        )
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout()

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout()

        self.assertIn("Timeout value must be between 10 and 1800 seconds.", err1.exception.args[0])
        self.assertIn("Timeout value must be between 10 and 1800 seconds.", err2.exception.args[0])


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_as3_deploy.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_as3_deploy.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_upsert_tenant_declaration(self, *args):
        declaration = load_fixture('as3_declare.json')
        set_module_args(dict(
            content=declaration,
            tenant='Sample_01',
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upsert_on_device = Mock(return_value=True)
        mm.client.post.return_value = {'code': 200, 'contents': {'results': [{'message': 'change'}]}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (6, 100))

    def test_remove_tenant_declaration(self, *args):
        set_module_args(dict(
            tenant='Sample_01',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 200},
            {'code': 202, 'contents': {'results': [{'code': 0, 'message': 'in progress', 'tenant': 'Sample_01'}]}},
            {'code': 200, 'contents': {'results': [{'code': 200, 'message': 'success', 'tenant': 'Sample_01'}]}},
            {'code': 404},
        ]
        mm.client.delete.return_value = {'code': 202, 'contents': {'id': 1}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (3, 100))
        self.assertEqual(mm.client.get.call_count, 4)

    def test_upsert_tenant_declaration_generates_errors(self, *args):
        declaration = load_fixture('as3_declaration_invalid.json')
        set_module_args(dict(
            content=declaration,
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('as3_invalid_declaration_task_start.json')
        ))
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('as3_error_message.json')
        ))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertEqual(
            "The operation has returned code: 422 with the following errors: /Sample_02/A1/web_pool2/members/0: "
            "should have required property 'bigip'", str(err.exception)
        )

    def test_upsert_multi_tenant_declaration_generates_errors(self, *args):
        declaration = load_fixture('as3_multiple_tenants_invalid.json')
        set_module_args(dict(
            content=declaration,
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=202, contents=load_fixture('as3_multi_tenant_declare_task_start.json')
        ))
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('as3_multi_tenant_error_message.json')
        ))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertEqual(
            "The operation for Sample_02 has returned code: 422 with the following message: "
            "0107176c:3: Invalid Node, the IP address 192.0.1.12 already exists.", err.exception.args[0]
        )

    def test_upsert_response_status_error(self, *args):
        set_module_args(dict(
            content='{}',
            tenant='fake_tenent',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_upsert_return_false(self, *args):
        set_module_args(dict(
            content='{}',
            tenant='fake_tenent',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post.return_value = {
            'code': 200,
            'contents': {'id': 1}
        }
        mm.wait_for_task = Mock(return_value={'results': [{'message': 'no change'}]})

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_upsert_on_device_timeout(self, *args):
        set_module_args(dict(
            content='{}',
            tenant='fake_tenent',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm._check_task_on_device = Mock(return_value={'results': {}})
        mm._get_errors_from_response = Mock(return_value=None)
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 1}}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    def test_empty_content_error(self, *args):
        set_module_args(dict(
            content=None,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Empty content cannot be specified when 'state' is 'present'.",
            err.exception.args[0]
        )

    def test_invalid_content_error(self, *args):
        set_module_args(dict(
            content='["invalid", "json"]',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "The provided 'content' could not be converted into valid json. If you "
            "are using the 'to_nice_json' filter, please remove it.",
            err.exception.args[0]
        )

    def test_remove_failure(self, *args):
        set_module_args(dict(
            tenant='all',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.resource_exists = Mock(return_value=True)
        mm.client.delete.return_value = {'code': 200, 'contents': {'id': 1}}
        mm.wait_for_task = Mock(return_value={'results': [{'message': 'no change'}]})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_present_return_false(self, *args):
        declaration = load_fixture('as3_declaration_invalid.json')
        set_module_args(dict(
            content=declaration,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_absent_return_false(self, *args):
        set_module_args(dict(
            tenant='fake_tenant',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.resource_exists = Mock(return_value=False)
        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_exists_response_status_failure(self, *args):
        set_module_args(dict(
            content='{"dummy": "dummy"}',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigip_as3_deploy, 'Connection')
    @patch.object(bigip_as3_deploy.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            content='declaration'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_as3_deploy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_as3_deploy, 'Connection')
    @patch.object(bigip_as3_deploy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            content='declaration'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_as3_deploy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_call_device_functions(self, *args):
        set_module_args(dict(
            tenant='all',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 204}
        ]
        mm.client.delete.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err1:
            mm._check_task_on_device('/')

        self.assertIn('service not available', err1.exception.args[0])

        self.assertFalse(mm.resource_exists())

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device()

        self.assertIn('service not available', err2.exception.args[0])
