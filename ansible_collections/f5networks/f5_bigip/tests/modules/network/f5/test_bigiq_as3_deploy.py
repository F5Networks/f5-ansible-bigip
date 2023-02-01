# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_as3_deploy
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_as3_deploy import (
    Parameters, ArgumentSpec, ModuleManager, ModuleParameters
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, AnsibleExitJson, AnsibleFailJson, exit_json, fail_json
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

    def test_module_parameters_content(self):
        args1 = dict()
        args2 = dict(content='{}')

        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        self.assertIsNone(p1.content)
        self.assertEqual(p2.content, {})


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_as3_deploy.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_as3_deploy.F5Client')
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

    def test_upsert_declaration(self, *args):
        declaration = load_fixture('as3_declare.json')
        set_module_args(dict(
            content=declaration,
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 'task_id'}}
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'results': [{'message': 'in progress'}]}},
            {'code': 200, 'contents': {'results': [{'message': 'success'}]}}
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)
        self.assertEqual(mm.client.get.call_count, 2)
        self.assertTrue(mm.want.timeout, (6, 100))

    def test_remove_declaration(self, *args):
        set_module_args(dict(
            tenant='fake_tenant',
            bigip_device='fake_device',
            timeout=600,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 'task_id'}}
        mm.wait_for_task = Mock(return_value=dict(results=[dict(message='success')]))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)
        self.assertTrue(mm.want.timeout, (6, 100))

    @patch.object(bigiq_as3_deploy, 'Connection')
    @patch.object(bigiq_as3_deploy.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        declaration = load_fixture('as3_declare.json')
        set_module_args(dict(
            content=declaration,
            timeout=600
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_as3_deploy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_as3_deploy, 'Connection')
    @patch.object(bigiq_as3_deploy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        declaration = load_fixture('as3_declare.json')
        set_module_args(dict(
            content=declaration,
            timeout=600
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_as3_deploy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        declaration = load_fixture('as3_declare.json')
        set_module_args(dict(
            content=declaration,
            tenant='fake_tenant',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        messages1 = {'message': 'declaration failed', 'errors': ['declaration is not valid']}
        messages2 = {'results': [{'message': 'declaration failed', 'errors': ['declaration is not valid']}]}

        res1 = mm._get_errors_from_response(messages=messages1)
        res2 = mm._get_errors_from_response(messages=messages2)

        self.assertListEqual(res1, ['declaration failed', 'declaration is not valid'])
        self.assertListEqual(res2, ['declaration failed', 'declaration is not valid'])

        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err1:
            mm._check_task_on_device(path='/')

        self.assertIn(
            'service not available',
            err1.exception.args[0]
        )

        mm._check_task_on_device = Mock(return_value={'results': []})
        mm._get_errors_from_response = Mock(side_effect=[['declaration failed', 'declaration is not valid'], None])

        with self.assertRaises(F5ModuleError) as err2:
            mm.wait_for_task(path='/', delay=1, period=10)

        self.assertIn(
            'declaration failed. declaration is not valid',
            err2.exception.args[0]
        )

        mm._get_errors_from_response = Mock(return_value=None)

        with self.assertRaises(F5ModuleError) as err3:
            mm.wait_for_task(path='/', delay=1, period=10)

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err3.exception.args[0]
        )

        mm.wait_for_task = Mock(return_value=None)

        mm.client.post.side_effect = [
            # remove_on_device
            {'code': 200, 'contents': {'id': 'task_id'}},
            {'code': 503, 'contents': 'service not available'},

            # upsert_on_device
            {'code': 200, 'contents': {'id': 'task_it'}},
            {'code': 503, 'contents': 'service not available'},
        ]

        res3 = mm.remove_on_device()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove_on_device()

        self.assertIn('service not available', err4.exception.args[0])

        res4 = mm.upsert_on_device()
        self.assertFalse(res4)

        with self.assertRaises(F5ModuleError) as err5:
            mm.upsert_on_device()

        self.assertIn('service not available', err5.exception.args[0])
