# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_do_deploy
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_do_deploy import (
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
            timeout=600
        )
        p = Parameters(params=args)
        assert p.content == dict(param1='foo', param2='bar')
        assert p.timeout == 600

    def test_module_parameters_timeout(self):
        args1 = dict(timeout=149)
        args2 = dict(timeout=3601)
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout

        self.assertIn(
            "Timeout value must be between 150 and 3600 seconds.",
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout

        self.assertIn(
            "Timeout value must be between 150 and 3600 seconds.",
            err2.exception.args[0]
        )

    def test_module_parameters_content(self):
        args = dict(content='{}')
        p = ModuleParameters(params=args)

        self.assertEqual(p.content, {})


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_do_deploy.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_do_deploy.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.patcher1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_start_declaration_task(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 200, 'contents': {'id': uuid}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['task_id'], uuid)
        self.assertEqual(results['message'], "DO async task started with id: {0}".format(uuid))

    def test_check_declaration_task_status(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
            timeout=500
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        # mm._check_task_on_device = Mock(return_value=response)
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'result': {'status': 'RUNNING'}}},
            {'code': 200, 'contents': {'result': {'status': 'FINISHED', 'message': 'success'}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': uuid}}
        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (5.0, 100))

    @patch.object(bigiq_do_deploy, 'Connection')
    @patch.object(bigiq_do_deploy.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_do_deploy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_do_deploy, 'Connection')
    @patch.object(bigiq_do_deploy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_do_deploy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        message = {'message': 'invalid config - rolled back', 'errors': ['invalid config']}

        res1 = mm._get_errors_from_response(message)
        self.assertEqual(res1, ['invalid config - rolled back', 'invalid config'])

        mm._get_errors_from_response = Mock(return_value=['invalid config - rolled back', 'invalid config'])
        mm.client.get.side_effect = [
            {'code': 422, 'contents': message},
            {'code': 503, 'contents': 'service not available'}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm._check_task_on_device(uuid)

        self.assertIn(
            'invalid config - rolled back. invalid config',
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            mm._check_task_on_device(uuid)

        self.assertIn('service not available', err2.exception.args[0])

        mm._check_task_on_device = Mock(return_value=tuple((503, 'service not available')))

        with self.assertRaises(F5ModuleError) as err3:
            mm.wait_for_task(uuid, 1, 10)

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err3.exception.args[0]
        )

        mm.wait_for_task = Mock(return_value=None)
        res2 = mm.query_task()
        self.assertFalse(res2)

        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err4:
            mm.upsert_on_device()

        self.assertIn('service not available', err4.exception.args[0])
