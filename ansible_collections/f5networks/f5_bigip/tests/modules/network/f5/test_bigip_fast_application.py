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
    Parameters, ArgumentSpec, ModuleManager
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
