# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_fast_application
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_application import (
    Parameters, ArgumentSpec, ModuleManager, ModuleParameters
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.client import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, AnsibleExitJson, AnsibleFailJson, fail_json, exit_json
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
            application='test_app',
            template='example/foobar',
            timeout=600,
        )
        p = Parameters(params=args)

        self.assertEqual(p.tenant, 'test_tenant')
        self.assertEqual(p.application, 'test_app')
        self.assertEqual(p.template, 'example/foobar')
        self.assertEqual(p.content, dict(param1='foo', param2='bar'))
        self.assertEqual(p.timeout, 600)

    def test_module_parameters_timeout(self):
        args1 = dict(timeout=9)
        args2 = dict(timeout=1801)
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout

        self.assertIn(
            "Timeout value must be between 10 and 1800 seconds.",
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout

        self.assertIn(
            "Timeout value must be between 10 and 1800 seconds.",
            err2.exception.args[0]
        )


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_application.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_application.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_create_fast_application(self, *args):
        declaration = load_fixture('new_fast_app.json')
        set_module_args(dict(
            content=declaration,
            template='examples/simple_http',
            state='create',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 200, 'contents': ['examples/simple_http']},
            {'code': 200, 'contents': {'message': 'in progress'}},
            {'code': 200, 'contents': {'message': 'success'}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'message': [{'id': 1}]}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (6, 100))
        self.assertEqual(results['template'], 'examples/simple_http')
        self.assertEqual(results['content'], declaration)

    def test_create_on_device_failure_no_change(self, *args):
        declaration = load_fixture('new_fast_app.json')
        set_module_args(dict(
            content=declaration,
            template='examples/simple_http',
            state='create',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.template_exists = Mock()
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'message': [{'id': 1}]}}
        ]
        mm.wait_for_task = Mock(return_value={'message': 'no change'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_fast_application(self, *args):
        declaration = load_fixture('fast_app_update.json')
        set_module_args(dict(
            content=declaration,
            tenant='sample_tenant',
            application='sample_app',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.wait_for_task = Mock(return_value={'message': 'success'})

        mm.client.get.return_value = {'code': 200}
        mm.client.patch.return_value = {'code': 200, 'contents': {'message': [{'id': 1}]}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (3, 100))
        self.assertEqual(results['tenant'], 'sample_tenant')
        self.assertEqual(results['application'], 'sample_app')
        self.assertEqual(results['content'], declaration)

    def test_update_application_not_found(self, *args):
        declaration = load_fixture('fast_app_update.json')
        set_module_args(dict(
            content=declaration,
            tenant='sample_tenant',
            application='sample_app',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f'The specified FAST Application: {mm.want.application} '
            f'in tenant: {mm.want.tenant} has not been found.',
            err.exception.args[0]
        )

    def test_upsert_on_device_failure_no_change(self, *args):
        declaration = load_fixture('fast_app_update.json')
        set_module_args(dict(
            content=declaration,
            tenant='sample_tenant',
            application='sample_app',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'message': [{'id': 1}]}}
        ]
        mm.wait_for_task = Mock(return_value={'message': 'no change'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_remove_fast_application(self, *args):
        set_module_args(dict(
            tenant='sample_tenant',
            application='sample_app',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.wait_for_task = Mock(return_value={'message': 'success'})
        mm.client.get.side_effect = [
            {'code': 200},
            {'code': 404},
        ]
        mm.client.delete.return_value = {'code': 200, 'contents': {'id': 1}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (3, 100))
        self.assertEqual(results['tenant'], 'sample_tenant')
        self.assertEqual(results['application'], 'sample_app')

    def test_absent_return_false(self, *args):
        set_module_args(dict(
            tenant='sample_tenant',
            application='sample_app',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_unable_to_remove_failure(self, *args):
        set_module_args(dict(
            tenant='sample_tenant',
            application='sample_app',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_purge_all_fast_applications(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.wait_for_task = Mock(return_value={'message': 'success'})
        mm.client.delete.return_value = {'code': 200, 'contents': {'id': 1}}

        results = mm.exec_module()

        self.assertEqual(mm.want.timeout, (3, 100))
        self.assertTrue(results['changed'])

    def test_purge_from_device_failure_no_change(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.delete.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'id': 1}}
        ]
        mm.wait_for_task = Mock(return_value={'message': 'no change'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    @patch.object(bigip_fast_application, 'Connection')
    @patch.object(bigip_fast_application.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            content='declaration',
            template='examples/simple_http'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_fast_application.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_fast_application, 'Connection')
    @patch.object(bigip_fast_application.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            content='declaration',
            template='examples/simple_http'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_fast_application.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_template_not_found_error(self, *args):
        set_module_args(dict(
            content='["invalid", "json"]',
            tenant='sample_tenant',
            template='examples/simple_http',
            application='sample_app',
            state='create',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 200, 'contents': [{'name': 'fake_template'}]},
            {'code': 404, 'contents': '404: template not found'}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn(
            f'The specified FAST template: {mm.want.template} has not been found.',
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn(
            '404: template not found',
            err2.exception.args[0]
        )

    def test_create_invalid_content_error(self, *args):
        set_module_args(dict(
            content='["invalid", "json"]',
            tenant='sample_tenant',
            template='examples/simple_http',
            application='sample_app',
            state='create',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.template_exists = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "The provided 'content' could not be converted into valid json. If you "
            "are using the 'to_nice_json' filter, please remove it.",
            err.exception.args[0]
        )

    def test_upsert_invalid_content_error(self, *args):
        set_module_args(dict(
            content='["invalid", "json"]',
            tenant='sample_tenant',
            template='examples/simple_http',
            application='sample_app',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "The provided 'content' could not be converted into valid json. If you "
            "are using the 'to_nice_json' filter, please remove it.",
            err.exception.args[0]
        )

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            content='["invalid", "json"]',
            tenant='sample_tenant',
            template='examples/simple_http',
            application='sample_app',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            required_together=self.spec.required_together
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err1:
            resp = {'message': 'declaration failed'}
            mm._check_for_errors_in_response(resp)

        self.assertIn('declaration failed', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            resp = {'message': 'declaration is invalid'}
            mm._check_for_errors_in_response(resp)

        self.assertIn('declaration is invalid', err2.exception.args[0])

        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err3:
            mm._check_task_on_device('/')

        self.assertIn('service not available', err3.exception.args[0])

        mm._check_task_on_device = Mock(return_value={'message': 'in progress'})
        mm._check_for_errors_in_response = Mock()

        with self.assertRaises(F5ModuleError) as err4:
            mm.wait_for_task(path='/', interval=1, period=10)

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err4.exception.args[0]
        )

        mm.client.delete.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err5:
            mm.remove_from_device()

        self.assertIn('service not available', err5.exception.args[0])
