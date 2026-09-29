# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import copy
import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_ucs_fetch
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs_fetch import (
    ModuleParameters, ArgumentSpec, ModuleManager
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
    def setUp(self):
        fixture_data.clear()

    def test_module_parameters(self):
        args = dict(
            backup='yes',
            create_on_missing='yes',
            encryption_password='my-password',
            dest='/tmp/foo.ucs',
            force='yes',
            fail_on_missing='no',
            src='remote.ucs',
            timeout=600
        )
        p = ModuleParameters(params=args)
        assert p.backup == 'yes'
        assert p.timeout == (6.0, 100)
        assert p.src == 'remote.ucs'

    def test_src_auto_generated(self):
        args = dict(
            dest='/tmp/foo.ucs'
        )
        p = ModuleParameters(params=args)
        self.assertTrue(p.src.endswith('.ucs'))

    def test_fulldest_is_dir(self):
        args = dict(
            dest='/tmp',
            src='remote.ucs'
        )
        p = ModuleParameters(params=args)
        with patch('os.path.isdir', return_value=True), patch('os.access', return_value=True):
            self.assertEqual(p.fulldest, '/tmp/remote.ucs')

    def test_fulldest_parent_exists(self):
        args = dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        )
        p = ModuleParameters(params=args)
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True):
            self.assertEqual(p.fulldest, '/tmp/foo.ucs')

    def test_fulldest_oserror_permission_denied(self):
        # Error Path 1: OSError with permission denied
        args = dict(
            dest='/restricted/foo.ucs',
            src='remote.ucs'
        )
        p = ModuleParameters(params=args)
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=False), \
             patch('os.stat', side_effect=OSError("permission denied")):
            with self.assertRaises(F5ModuleError) as ctx:
                p.fulldest
            self.assertIn("is not accessible", str(ctx.exception))

    def test_fulldest_oserror_not_exists(self):
        # Error Path 2: OSError without permission denied
        args = dict(
            dest='/nonexistent/foo.ucs',
            src='remote.ucs'
        )
        p = ModuleParameters(params=args)
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=False), \
             patch('os.stat', side_effect=OSError("no such file or directory")):
            with self.assertRaises(F5ModuleError) as ctx:
                p.fulldest
            self.assertIn("does not exist", str(ctx.exception))

    def test_fulldest_not_writable(self):
        # Error Path 3: Destination directory not writable
        args = dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        )
        p = ModuleParameters(params=args)
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=False):
            with self.assertRaises(F5ModuleError) as ctx:
                p.fulldest
            self.assertIn("not writable", str(ctx.exception))

    def test_timeout_invalid_low(self):
        # Error Path 4a: Timeout value under 150
        args = dict(
            dest='/tmp/foo.ucs',
            timeout=100
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as ctx:
            p.timeout
        self.assertIn("Timeout value must be between 150 and 1800 seconds.", str(ctx.exception))

    def test_timeout_invalid_high(self):
        # Error Path 4b: Timeout value over 1800
        args = dict(
            dest='/tmp/foo.ucs',
            timeout=2000
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as ctx:
            p.timeout
        self.assertIn("Timeout value must be between 150 and 1800 seconds.", str(ctx.exception))

    def test_options_empty(self):
        args = dict(
            dest='/tmp/foo.ucs'
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.options, [])

    def test_changes_to_return_exception(self):
        c = bigip_ucs_fetch.Changes(params={})
        with patch.object(bigip_ucs_fetch.Changes, '_filter_params', side_effect=Exception('Filter error')):
            with self.assertRaises(Exception):
                c.to_return()


class TestV1Manager(unittest.TestCase):
    def setUp(self):
        fixture_data.clear()
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs_fetch.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_start_create_task(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            src='remote.ucs',
            dest='/tmp/cs_backup.ucs',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=False)
        mm.create_async_task_on_device = Mock(return_value=task_id)
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['task_id'] == task_id
        assert results['message'] == 'UCS async task started with id: {0}'.format(task_id)

    def test_start_create_task_with_encryption_password(self, *args):
        set_module_args(dict(
            src='remote.ucs',
            dest='/tmp/cs_backup.ucs',
            encryption_password='secret_passphrase'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post.return_value = {'code': 200, 'contents': {'_taskId': 'task-123'}}
        mm.client.put.return_value = {'code': 200, 'contents': {}}

        task_id = mm.create_async_task_on_device()
        self.assertEqual(task_id, 'task-123')
        mm.client.post.assert_called_once_with(
            "/mgmt/tm/task/sys/ucs",
            data={
                'command': 'save',
                'name': 'remote.ucs',
                'options': [{'passphrase': 'secret_passphrase'}]
            }
        )

    def test_check_task_download_ucs(self, *args):
        set_module_args(dict(
            backup='yes',
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='e7550a12-994b-483f-84ee-761eb9af6750',
            timeout=400
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.async_wait = Mock(return_value=True)
        mm._get_backup_file = Mock(return_value='/tmp/foo.backup')
        mm.download_from_device = Mock(return_value=True)
        mm._set_checksum = Mock(return_value=12345)
        mm._set_md5sum = Mock(return_value=54321)

        p1 = patch('os.path.exists', return_value=True)
        p1.start()
        p2 = patch('os.path.isdir', return_value=False)
        p2.start()

        results = mm.exec_module()

        p1.stop()
        p2.stop()

        assert results['changed'] is True

    def test_update_file_exists_force_false(self, *args):
        # Error Path 5: File already exists and force=False
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            force=False
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=False), \
             patch('os.access', return_value=True):
            with self.assertRaises(F5ModuleError) as ctx:
                mm.update()
            self.assertIn("already exists", str(ctx.exception))

    def test_update_file_exists_force_true(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            force=True
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.execute = Mock(return_value=True)
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=False), \
             patch('os.access', return_value=True):
            mm.update()
            mm.execute.assert_called_once()

    def test_execute_ioerror(self, *args):
        # Error Path 6: IOError raised during execute/download
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.download = Mock(side_effect=IOError("Permission denied"))
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True):
            with self.assertRaises(F5ModuleError) as ctx:
                mm.execute()
            self.assertIn("Failed to copy", str(ctx.exception))

    def test_execute_with_backup(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            backup=True
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.download = Mock(return_value=True)
        mm._get_backup_file = Mock(return_value='/tmp/foo.ucs.bak')
        mm.module.sha1 = Mock(return_value='sha1hash')
        mm.module.md5 = Mock(return_value='md5hash')
        mm.module.load_file_common_arguments = Mock(return_value={})
        mm.module.set_fs_attributes_if_different = Mock(return_value=True)

        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True):
            res = mm.execute()
            self.assertTrue(res)
            self.assertEqual(mm.changes.backup_file, '/tmp/foo.ucs.bak')

    def test_set_checksum_and_md5sum_valueerror(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.module.sha1 = Mock(side_effect=ValueError("Sha1 failed"))
        mm.module.md5 = Mock(side_effect=ValueError("Md5 failed"))

        with patch('os.path.isdir', return_value=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True):
            mm._set_checksum()
            mm._set_md5sum()
            self.assertIsNone(mm.want.checksum)
            self.assertIsNone(mm.want.md5sum)

    def test_create_fail_on_missing_true(self, *args):
        # Error Path 7: fail_on_missing is True
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            fail_on_missing=True
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        with self.assertRaises(F5ModuleError) as ctx:
            mm.create()
        self.assertIn("was not found", str(ctx.exception))

    def test_create_fail_on_missing_false_create_on_missing_false(self, *args):
        # Error Path 8: create_on_missing is False
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            fail_on_missing=False,
            create_on_missing=False
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        with self.assertRaises(F5ModuleError) as ctx:
            mm.create()
        self.assertIn("was not found", str(ctx.exception))

    def test_create_check_mode(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            _ansible_check_mode=True
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        res = mm.create()
        self.assertTrue(res)

    def test_create_async_task_on_device_failure(self, *args):
        # Error Path 9: API post returns error code
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post.return_value = {'code': 400, 'contents': 'Invalid parameter'}
        with self.assertRaises(F5ModuleError) as ctx:
            mm.create_async_task_on_device()
        self.assertIn("Invalid parameter", str(ctx.exception))

    def test_start_task_on_device_success(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.put.return_value = {'code': 200, 'contents': {}}
        res = mm._start_task_on_device("task-123")
        self.assertTrue(res)

    def test_start_task_on_device_failure(self, *args):
        # Error Path 10: API put returns error code
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.put.return_value = {'code': 400, 'contents': 'Failed to validate'}
        with self.assertRaises(F5ModuleError) as ctx:
            mm._start_task_on_device("task-123")
        self.assertIn("Failed to validate", str(ctx.exception))

    def test_check_task_exists_on_device_success(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='task-123'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 200, 'contents': {}}
        res = mm.check_task_exists_on_device("task-123")
        self.assertTrue(res)

    def test_check_task_exists_on_device_failure(self, *args):
        # Error Path 11: Task not found on device
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='task-123'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 404, 'contents': 'Not found'}
        with self.assertRaises(F5ModuleError) as ctx:
            mm.check_task_exists_on_device("task-123")
        self.assertIn("The task with the given task_id: task-123 does not exist.", str(ctx.exception))

    def test_async_wait_task_completed(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='task-123'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.check_task_exists_on_device = Mock(return_value=True)
        mm.client.get.return_value = {
            'code': 200,
            'contents': {'_taskState': 'COMPLETED'}
        }
        res = mm.async_wait("task-123")
        self.assertTrue(res)

    def test_async_wait_task_failed(self, *args):
        # Error Path 12: Async task failed unexpectedly
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='task-123'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.check_task_exists_on_device = Mock(return_value=True)
        mm.client.get.return_value = {
            'code': 200,
            'contents': {'_taskState': 'FAILED'}
        }
        with self.assertRaises(F5ModuleError) as ctx:
            mm.async_wait("task-123")
        self.assertIn("Task failed unexpectedly.", str(ctx.exception))

    def test_async_wait_timeout(self, *args):
        # Error Path 13: Module timeout reached
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='task-123',
            timeout=150
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.check_task_exists_on_device = Mock(return_value=True)
        mm.client.get.return_value = {
            'code': 200,
            'contents': {'_taskState': 'RUNNING'}
        }
        with self.assertRaises(F5ModuleError) as ctx:
            mm.async_wait("task-123")
        self.assertIn("Module timeout reached", str(ctx.exception))

    def test_download_failed(self, *args):
        # Error Path 14: Failed to download remote file
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.download_from_device = Mock(return_value=False)
        with patch('os.path.exists', return_value=False):
            with self.assertRaises(F5ModuleError) as ctx:
                mm.download()
            self.assertIn("Failed to download the remote file", str(ctx.exception))

    def test_read_current_from_device_success(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 200, 'contents': {'items': []}}
        res = mm.read_current_from_device()
        self.assertEqual(res, {'items': []})

    def test_read_current_from_device_failure(self, *args):
        # Error Path 15: read_current_from_device non-200 response
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 500, 'contents': 'Internal REST error'}
        with self.assertRaises(F5ModuleError) as ctx:
            mm.read_current_from_device()
        self.assertIn("Internal REST error", str(ctx.exception))

    def test_read_current_no_items(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value={'kind': 'tm:sys:ucs:ucscollectionstate'})
        res = mm.read_current()
        self.assertEqual(res, [])

    def test_exists_true_and_false(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='foo.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        fixture = copy.deepcopy(load_fixture('load_ucs_files.json'))
        mm.read_current_from_device = Mock(return_value=fixture)

        self.assertTrue(mm.exists())

        mm.want.update({'src': 'bar.ucs'})
        self.assertFalse(mm.exists())

    def test_only_create_file_true(self, *args):
        set_module_args(dict(
            src='foo.ucs',
            only_create_file=True
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=True)
        mm.update = Mock()

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        mm.update.assert_not_called()

    def test_exec_module_telemetry(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.plugin.telemetry.return_value = True
        mm.client.platform = 'BIG-IP'
        mm.present = Mock()
        mm.changes.to_return = Mock(return_value={})

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.m2.assert_called_once()

    def test_download_from_device(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()

        with patch('os.path.exists', return_value=True):
            res = mm.download_from_device('/tmp/foo.ucs')
            self.assertTrue(res)

        with patch('os.path.exists', return_value=False):
            res = mm.download_from_device('/tmp/foo.ucs')
            self.assertFalse(res)


class TestMainFunction(unittest.TestCase):
    def setUp(self):
        fixture_data.clear()
        self.mock_module = patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json)
        self.mock_module.start()

    def tearDown(self):
        self.mock_module.stop()

    @patch.object(bigip_ucs_fetch, 'Connection')
    @patch.object(bigip_ucs_fetch.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': True}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        with self.assertRaises(AnsibleExitJson) as result:
            bigip_ucs_fetch.main()
        self.assertTrue(result.exception.args[0]['changed'])

    @patch.object(bigip_ucs_fetch, 'Connection')
    @patch.object(bigip_ucs_fetch.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('UCS fetch failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.ucs',
            src='remote.ucs'
        ))
        with self.assertRaises(AnsibleFailJson) as result:
            bigip_ucs_fetch.main()
        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('UCS fetch failed.', result.exception.args[0]['msg'])
