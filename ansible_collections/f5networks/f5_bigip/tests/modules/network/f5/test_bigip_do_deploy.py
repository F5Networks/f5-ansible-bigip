# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import ConnectionError

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_do_deploy
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_do_deploy import (
    ModuleParameters, ArgumentSpec, ModuleManager
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

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
            timeout=600
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.content, dict(param1='foo', param2='bar'))
        self.assertEqual(p.timeout, (6.0, 100))

    @patch.object(bigip_do_deploy.json, 'loads', Mock(return_value='null'))
    def test_module_parameters(self):
        args = dict(
            content=''
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.content, 'null')

    def test_module_parameters_timeout(self):
        args1 = dict(timeout=149)
        args2 = dict(timeout=3601)
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout()

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout()

        self.assertIn(
            "Timeout value must be between 150 and 3600 seconds.",
            err1.exception.args[0]
        )
        self.assertIn(
            "Timeout value must be between 150 and 3600 seconds.",
            err2.exception.args[0]
        )


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_do_deploy.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_do_deploy.send_teem')
        self.m3 = self.p3.start()
        self.m3.return_value = True
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
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
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 200, 'contents': {'id': uuid, 'result': {'code': 200, 'message': 'success'}}}

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(results['task_id'], uuid)

    def test_check_declaration_task_status(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
            timeout=500
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 300, 'contents': {}},
            {'code': 200},
            {'code': 202},
            {'code': 200, 'contents': {'result': {'status': 'FINISHED', 'message': 'success'}}}
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.want.timeout, (5.0, 100))
        self.assertEqual(mm.client.get.call_count, 4)

    def test_check_declaration_task_status_unit_restarts(self, *args):
        response = (400, None)
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
            timeout=500
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm._check_task_on_device = Mock(return_value=response)
        mm.device_is_ready = Mock(return_value=False)
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(results['task_id'], uuid)
        self.assertEqual(results['message'], "Device is restarting services, unable to check task status.")
        self.assertEqual(mm.want.timeout, (5, 100))

    def test_upsert_response_status_failure(self, *args):
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_wait_for_task_timeout(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        mm._check_task_on_device = Mock(return_value=(202, {'result': {'status': 'RUNNING'}}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    def test_device_is_ready_connection_error(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        mm._check_task_on_device = Mock(return_value=(503, {}))
        mm.client.get.side_effect = ConnectionError('connection error')
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(results['task_id'], uuid)
        self.assertEqual(
            results['message'],
            'Device is restarting services, unable to check task status.'
        )

    def test_device_is_ready_return_false(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            ConnectionError('connection error'),
            {'code': 503}
        ]
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(results['task_id'], uuid)
        self.assertEqual(
            results['message'],
            'Device is restarting services, unable to check task status.'
        )

    def test_task_exist_on_device_failure(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        mm._check_task_on_device = Mock(return_value=(503, {}))
        mm.device_is_ready = Mock(return_value=True)
        mm.client.get.return_value = {'code': 503}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f"The task with the given task_id: {uuid} does not exist.",
            err.exception.args[0]
        )

    def test_get_errors_from_response(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        expected = ['invalid config - rolled back', '404: not found']
        message = {'message': 'invalid config - rolled back', 'errors': ['404: not found']}
        result = mm._get_errors_from_response(message=message)

        self.assertEqual(expected, result)

    def test_check_task_on_device(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)
        contents = {'message': 'invalid config - rolled back', 'errors': ['404: Unprocessed entity']}
        mm.client.get.return_value = {'code': 422, 'contents': contents}
        with self.assertRaises(F5ModuleError) as err:
            mm._check_task_on_device(uuid)

        self.assertIn(
            'invalid config - rolled back. 404: Unprocessed entity',
            err.exception.args[0]
        )

    def test_dry_run_declaration(self, *args):
        uuid = "b429c5ad-5ed9-4a61-83ab-bbcf27af8e26"
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
            dry_run='yes'
        ))

        expected = {'async': True, 'controls': {'trace': True, 'traceResponse': True, 'dryRun': True}}
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = dict(code=202, contents=dict(id=uuid))
        mm.client.get.return_value = dict(code=200, contents=load_fixture('do_dry_run_result.json'))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertTrue(len(results['diff']) == 9)
        self.assertLessEqual(expected.items(), mm.client.post.call_args[1]['data'].items())
        self.assertEqual(results['message'], 'Dry run completed successfully.')

    def test_dry_run_declaration_fails(self, *args):
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
            dry_run='yes'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = dict(code=403, contents='forbidden')

        with self.assertRaises(F5ModuleError) as err:
            mm._start_dry_run_on_device()

        self.assertIn('forbidden', err.exception.args[0])

    def test_invalid_content_error_dry_run(self, *args):
        set_module_args(dict(
            content='["invalid", "json"]',
            dry_run='yes',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "The provided 'content' could not be converted into valid json. If you "
            "are using the 'to_nice_json' filter, please remove it.",
            err.exception.args[0]
        )

    def test_empty_content_error_dry_run(self, *args):
        set_module_args(dict(
            dry_run='yes',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn("Empty content cannot be specified when 'dry_run' is 'yes'", err.exception.args[0])

    @patch.object(bigip_do_deploy, 'Connection')
    @patch.object(bigip_do_deploy.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            content='declaration'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_do_deploy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_do_deploy, 'Connection')
    @patch.object(bigip_do_deploy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            content='declaration'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_do_deploy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
