# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_config
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_config import (
    Parameters, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
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
            save='yes',
            reset='yes',
            merge_content='asdasd',
            verify='no',
        )
        p = Parameters(params=args)
        self.assertEqual(p.save, 'yes')
        self.assertEqual(p.reset, 'yes')
        self.assertEqual(p.merge_content, 'asdasd')

    def test_module_parameters_timeout_attribute(self):
        p1 = Parameters(params=dict(timeout=149))
        p2 = Parameters(params=dict(timeout=1801))

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout

        self.assertIn('Timeout value must be between 150 and 1800 seconds.', err1.exception.args[0])
        self.assertIn('Timeout value must be between 150 and 1800 seconds.', err2.exception.args[0])


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_config.send_teem')
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_config.F5Client')
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_config.tmos_version')
        self.p1.start()
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.m3 = self.p3.start()
        self.m3.return_value = MagicMock()
        self.m4 = self.p4.start()
        self.m4.return_value = '16.1.1'
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_start_save_config_task(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            save='yes'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 202, 'contents': {'_taskId': task_id}}
        mm.client.put.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['task_id'], task_id)
        self.assertEqual(results['message'], 'Save config async task started with id: {0}'.format(task_id))

    def test_start_save_config_task_error(self, *args):
        set_module_args(dict(
            save='yes'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 404, 'contents': 'This module has failed'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('This module has failed', err.exception.args[0])

    def test_start_merge_config_task(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.side_effect = [
            {'code': 200},
            {'code': 200, 'contents': {'_taskId': task_id}}
        ]
        mm.client.put.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.plugin.upload_file.called)
        self.assertEqual(results['task_id'], task_id)
        self.assertEqual(results['message'], 'Merge config async task started with id: {0}'.format(task_id))

    def test_start_merge_config_task_upload_failure(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.plugin.upload_file.side_effect = F5ModuleError()
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to upload the file.', err.exception.args[0])
        self.assertTrue(mm.client.plugin.upload_file.called)

    def test_start_merge_config_task_move_failure(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upload_to_device = Mock()
        mm.client.post.return_value = {'code': 503, 'contents': 'Service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Service not available', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_start_merge_config_task_merge_failure(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upload_to_device = Mock()
        mm.move_on_device = Mock()
        mm.client.post.return_value = {'code': 503, 'contents': 'Service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Service not available', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_start_reset_config_task(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            reset='yes'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 200, 'contents': {'_taskId': task_id}}
        mm.client.put.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['task_id'], task_id)
        self.assertEqual(results['message'], 'Load config defaults async task started with id: {0}'.format(task_id))

    def test_start_reset_config_task_failure(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            reset='yes'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.post.return_value = {'code': 503, 'contents': 'Failed to reset device'}
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to reset device', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_verify_config(self, *args):
        set_module_args(dict(
            verify='yes',
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upload_to_device = Mock(return_value=True)
        mm.move_on_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=200, contents=dict()))
        results = mm.exec_module()

        self.assertEqual(mm.client.post.call_count, 2)
        self.assertFalse(results['changed'])
        self.assertEqual(results['message'], 'Validating configuration process succeeded.')

    def test_verify_config_verify_failure(self, *args):
        set_module_args(dict(
            verify='yes',
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upload_to_device = Mock(return_value=True)
        mm.move_on_device = Mock(return_value=True)
        mm.client.post.return_value = {'code': 503, 'contents': 'Service not available'}

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('Service not available', err1.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_verify_config_remove_tmpfile_failure(self, *args):
        set_module_args(dict(
            verify='yes',
            merge_content='asdas'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upload_to_device = Mock(return_value=True)
        mm.move_on_device = Mock(return_value=True)
        mm.verify_on_device = Mock(return_value=True)
        mm.client.post.return_value = {'code': 503, 'contents': 'Service not available'}

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('Service not available', err1.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_with_taskid(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=task_id
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 200},
            {'code': 200},
            {'code': 503},
            {'code': 200},
            {'code': 200, 'contents': {'_taskState': 'COMPLETED'}},
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 5)

    def test_taskid_device_not_ready(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=task_id
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.return_value = {'code': 503}

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(results['message'], 'Device is restarting services, unable to check task status.')
        self.assertEqual(mm.client.get.call_count, 1)

    def test_taskid_call_functions(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=task_id
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.device_is_ready = Mock(side_effect=[True, False])

        mm.client.get.side_effect = [
            {'code': 503},
            {'code': 200},
            {'code': 200, 'contents': {'_taskState': 'FAILED'}},
            {'code': 200},
            {'code': 404}
        ]
        with self.assertRaises(F5ModuleError) as err1:
            mm.check_task_exists_on_device(task_id)

        self.assertIn(f"The task with the given task_id: {task_id} does not exist.", err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.async_wait(task_id)

        self.assertIn('Task failed unexpectedly.', err2.exception.args[0])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['message'], 'Device is restarting services, unable to check task status.')

    def test_taskid_call_timeout_error(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=task_id
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.device_is_ready = Mock(return_value=True)
        mm.check_task_exists_on_device = Mock()
        mm.client.get.return_value = {'code': 503}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    def test_helper_functions(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=task_id
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.client.put.return_value = {'code': 503, 'contents': 'Service not available'}
        mm.client.get.side_effect = ConnectionError
        resp = mm.device_is_ready()

        with self.assertRaises(F5ModuleError) as err:
            mm._start_task_on_device(task_id)

        self.assertIn('Service not available', err.exception.args[0])
        self.assertFalse(resp)

    @patch.object(bigip_config, 'Connection')
    @patch.object(bigip_config.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            verify='yes',
            merge_content='asdas'
        )
        )

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_config.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_config, 'Connection')
    @patch.object(bigip_config.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            verify='yes',
            merge_content='asdas'
        )
        )

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_config.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
