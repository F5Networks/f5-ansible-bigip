# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_qkview
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_qkview import (
    Parameters, ModuleManager, ArgumentSpec, BulkLocationManager, MadmLocationManager
)

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import (
    Mock, patch
)
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
            filename='foo.qkview',
            asm_request_log=False,
            max_file_size=1024,
            complete_information=True,
            exclude_core=True,
            force=False,
            exclude=['audit', 'secure'],
            dest='/tmp/foo.qkview'
        )
        p = Parameters(params=args)

        self.assertTrue(p.filename, 'foo.qkview')
        self.assertIsNone(p.asm_request_log)
        self.assertTrue(p.max_file_size == '-s 1024')
        self.assertTrue(p.complete_information == '-c')
        self.assertTrue(p.exclude_core == '-C')
        self.assertFalse(p.force)
        self.assertTrue(p.dest == '/tmp/foo.qkview')
        self.assertIn('audit', p.exclude)
        self.assertIn('secure', p.exclude_raw)

    def test_module_asm_parameter(self):
        args = dict(
            asm_request_log=True,
        )
        p = Parameters(params=args)

        self.assertTrue(p.asm_request_log, '-o asm-request-log')

    def test_parameter_raises(self):
        args = dict(
            timeout=9,
            filename='$%##$#'
        )

        p = Parameters(params=args)

        with self.assertRaises(F5ModuleError) as err1:
            p.timeout()

        self.assertIn('Timeout value must be between 10 and 1800 seconds', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            p.filename

        self.assertIn('The provided filename must contain word characters only', err2.exception.args[0])


class TestModuleManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_qkview.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('os.path.exists')
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

    def test_create_qkview_default_options(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_cli_script_status.json')),
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=load_fixture('load_cli_task_start.json')))
        tm.client.get = Mock(side_effect=[
            dict(code=503, contents='server error'),
            dict(code=200, contents=dict()),
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        results = tm.exec_module()

        self.assertFalse(results['changed'])
        self.assertIn(
            'set cmd [lreplace $tmsh::argv 0 0];', tm.client.post.call_args_list[0][1]['data']['apiAnonymous']
        )
        self.assertIn(
            '/usr/bin/qkview -f localhost.localdomain.qkview',
            tm.client.post.call_args_list[1][1]['data']['utilCmdArgs']
        )
        self.assertIn(
            '-c "tmsh delete cli script /Common/__ansible_mkqkview"',
            tm.client.post.call_args_list[2][1]['data']['utilCmdArgs']
        )
        self.assertIn(
            '/var/tmp/localhost.localdomain.qkview /var/config/rest/madm/localhost.localdomain.qkview',
            tm.client.post.call_args_list[3][1]['data']['utilCmdArgs']
        )
        self.assertIn(
            '/var/config/rest/madm/localhost.localdomain.qkview',
            tm.client.post.call_args_list[4][1]['data']['utilCmdArgs']
        )
        self.assertTrue(tm.client.put.call_count == 1)
        self.assertTrue(tm.client.get.call_count == 3)

    def test_create_qkview_default_options_overwrite_script(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        tm.client.post = Mock(side_effect=[
            dict(code=409, contents=dict()),
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        tm.client.put = Mock(side_effect=[
            dict(code=200, contents=dict()),
            dict(code=202, contents=load_fixture('load_cli_task_start.json'))
        ])
        tm.client.get = Mock(side_effect=[
            dict(code=503, contents='server error'),
            dict(code=200, contents=dict()),
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        results = tm.exec_module()

        self.assertFalse(results['changed'])
        self.assertTrue(tm.client.post.call_count == 5)
        self.assertTrue(tm.client.put.call_count == 2)
        self.assertTrue(tm.client.get.call_count == 3)

    @patch.object(bigip_qkview, 'Connection')
    @patch.object(bigip_qkview.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_qkview.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_qkview, 'Connection')
    @patch.object(bigip_qkview.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_qkview.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(bigip_qkview, 'HAS_PACKAGING', False)
    @patch.object(bigip_qkview, 'Connection')
    @patch.object(bigip_qkview.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_import_error(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_qkview.PACKAGING_IMPORT_ERROR = "failed to import the 'packaging' package"
            bigip_qkview.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn(
            'Failed to import the required Python library (packaging)',
            result.exception.args[0]['msg']
        )

    def test_on_device_methods(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        bm = BulkLocationManager(module=module)
        bm.client.plugin = Mock()
        bm.client.plugin.download_file = Mock()

        with patch.object(bigip_qkview.os.path, 'exists', Mock(return_value=False)):
            res1 = tm._download_file()
            res2 = bm._download_file()

        self.assertFalse(res1)
        self.assertFalse(res2)

        res3 = bm._download_file()

        self.assertTrue(res3)

        tm.client.post = Mock(return_value=dict(code=500, contents='server error'))
        tm.client.put = Mock(return_value=dict(code=401, contents='forbidden'))

        with self.assertRaises(F5ModuleError) as err1:
            tm._move_qkview_to_download()
        self.assertEqual('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            tm._remove_temporary_cli_script_from_device()
        self.assertEqual('server error', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            tm._create_async_task_on_device()
        self.assertEqual('server error', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            tm._create_temporary_cli_script_on_device(dict())
        self.assertEqual('server error', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            tm._delete_qkview()
        self.assertEqual('server error', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            tm._exec_async_task_on_device('foo')
        self.assertEqual('forbidden', err6.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            tm._update_temporary_cli_script_on_device('foo')
        self.assertEqual('forbidden', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            tm.client.get = Mock(return_value=dict(code=202, contents={'_taskState': 'STARTED'}))
            tm._wait_for_async_task_to_finish_on_device('foo')
        self.assertEqual('Operation timed out.', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err8:
            tm.client.get = Mock(return_value=dict(code=202, contents={'_taskState': 'FAILED'}))
            tm._wait_for_async_task_to_finish_on_device('foo')
        self.assertEqual('qkview creation task failed unexpectedly.', err8.exception.args[0])

        with self.assertRaises(F5ModuleError) as err9:
            tm.client.post = Mock(return_value=dict(code=202, contents={'commandResult': 'failed to remove file'}))
            tm._remove_temporary_cli_script_from_device()
        self.assertIn('failed to remove file', err9.exception.args[0])

    def test_class_methods(self, *args):
        set_module_args(dict(
            dest='/tmp/foo.qkview',
            force=False,
            exclude=['foo']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        tm = MadmLocationManager(module=module, client=Mock())

        with self.assertRaises(F5ModuleError) as err1:
            tm.present()
        self.assertIn("The specified 'dest' file already exists.", err1.exception.args[0])

        with patch.object(bigip_qkview.os.path, 'exists', Mock(return_value=False)):
            with self.assertRaises(F5ModuleError) as err2:
                tm.present()
        self.assertIn("The directory of your 'dest' file does not exist", err2.exception.args[0])

        set_module_args(dict(
            dest='/tmp/foo.qkview',
            exclude=['foo']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods to force specific logic in the module to happen
        tm = MadmLocationManager(module=module, client=Mock())

        with self.assertRaises(F5ModuleError) as err3:
            tm.present()
        self.assertIn("The specified excludes must be in the following list", err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            tm.execute_on_device = Mock(return_value=False)
            tm.execute()
        self.assertIn('Failed to create qkview on device', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            tm.execute_on_device = Mock(return_value=True)
            tm._move_qkview_to_download = Mock(return_value=False)
            tm.execute()
        self.assertIn('Failed to move the file to a downloadable location', err5.exception.args[0])

        with patch.object(bigip_qkview.os.path, 'exists', Mock(return_value=False)):
            with self.assertRaises(F5ModuleError) as err6:
                tm.execute_on_device = Mock(return_value=True)
                tm._move_qkview_to_download = Mock(return_value=True)
                tm._download_file = Mock(return_value=True)
                tm.execute()
        self.assertIn('Failed to save the qkview to local disk', err6.exception.args[0])

    def test_module_manager_methods(self):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        fake_manager = Mock(return_value=Mock())
        mm.get_manager = Mock(return_value=fake_manager)

        with patch.object(bigip_qkview, 'tmos_version', Mock(return_value='15.0.0')):
            fake_manager.exec_module.return_value = dict(response='not 13.0.0')
            res1 = mm.exec_module()
        self.assertDictEqual(res1, {'response': 'not 13.0.0'})

        with patch.object(bigip_qkview, 'tmos_version', Mock(return_value='13.0.0')):
            fake_manager.exec_module.return_value = dict(response='is 13.0.0')
            res2 = mm.exec_module()
        self.assertDictEqual(res2, {'response': 'is 13.0.0'})

    def test_get_manager(self):
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        res3 = mm.get_manager('madm')
        res4 = mm.get_manager('bulk')

        self.assertTrue(isinstance(res3, MadmLocationManager))
        self.assertTrue(isinstance(res4, BulkLocationManager))

    def test_timeout_boundary_lower(self):
        """Test timeout at lower boundary (10 seconds)"""
        args = dict(timeout=10)
        p = Parameters(params=args)

        interval, divisor = p.timeout
        self.assertEqual(interval, 1)
        self.assertEqual(divisor, 10)

    def test_timeout_boundary_upper(self):
        """Test timeout at upper boundary (1800 seconds)"""
        args = dict(timeout=1800)
        p = Parameters(params=args)

        interval, divisor = p.timeout
        self.assertEqual(interval, 18)
        self.assertEqual(divisor, 100)

    def test_timeout_divisor_threshold(self):
        """Test timeout divisor changes at 100 seconds"""
        # At 99 seconds, divisor should be 10
        args_99 = dict(timeout=99)
        p_99 = Parameters(params=args_99)
        interval_99, divisor_99 = p_99.timeout
        self.assertEqual(divisor_99, 10)

        # At 100 seconds, divisor should be 100
        args_100 = dict(timeout=100)
        p_100 = Parameters(params=args_100)
        interval_100, divisor_100 = p_100.timeout
        self.assertEqual(divisor_100, 100)

    def test_exclude_core_option(self):
        """Test exclude_core parameter transforms correctly (PINS EXISTING BUG)"""
        # NOTE: This test documents a bug in bigip_qkview.py:154-159
        # The exclude_core property incorrectly reads self._values['exclude'] instead of
        # self._values['exclude_core'], so exclude_core=True is ignored and only checked
        # if the 'exclude' list is present. This is incorrect behavior but currently expected.
        # If this bug is fixed in the module, this test will fail and must be updated to
        # verify correct behavior (exclude_core=True should return '-C' regardless of exclude).
        args = dict(exclude_core=True)
        p = Parameters(params=args)

        # Due to bug: exclude_core is ignored when exclude is not set
        self.assertIsNone(p.exclude_core)

        # Due to bug: exclude_core returns '-C' only when exclude list is present
        args_with_exclude = dict(exclude_core=True, exclude=['audit'])
        p_with_exclude = Parameters(params=args_with_exclude)
        self.assertEqual(p_with_exclude.exclude_core, '-C')

    def test_exclude_options_single(self):
        """Test single exclude option"""
        for exclude_item in ['audit', 'secure', 'bash_history']:
            args = dict(exclude=[exclude_item])
            p = Parameters(params=args)

            self.assertIsNotNone(p.exclude)
            self.assertIn(exclude_item, p.exclude)
            self.assertIn(exclude_item, p.exclude_raw)

    def test_exclude_options_multiple(self):
        """Test multiple exclude options"""
        args = dict(exclude=['audit', 'secure', 'bash_history'])
        p = Parameters(params=args)

        self.assertIsNotNone(p.exclude)
        self.assertIn('audit', p.exclude)
        self.assertIn('secure', p.exclude)
        self.assertIn('bash_history', p.exclude)
        self.assertEqual(len(p.exclude_raw), 3)

    def test_exclude_all_option(self):
        """Test exclude with 'all' option"""
        args = dict(exclude=['all'])
        p = Parameters(params=args)

        self.assertIsNotNone(p.exclude)
        self.assertIn('all', p.exclude)
        self.assertEqual(p.exclude_raw, ['all'])

    def test_complete_information_option_true(self):
        """Test complete_information parameter transforms correctly"""
        args = dict(complete_information=True)
        p = Parameters(params=args)

        self.assertEqual(p.complete_information, '-c')

    def test_complete_information_option_false(self):
        """Test complete_information parameter is None when false"""
        args = dict(complete_information=False)
        p = Parameters(params=args)

        self.assertIsNone(p.complete_information)

    def test_max_file_size_option(self):
        """Test max_file_size parameter transforms correctly"""
        args = dict(max_file_size=2048)
        p = Parameters(params=args)

        self.assertEqual(p.max_file_size, '-s 2048')

    def test_all_options_together(self):
        """Test all options working together"""
        args = dict(
            filename='test_qkview.qkview',
            asm_request_log=True,
            max_file_size=5120,
            complete_information=True,
            exclude_core=True,
            exclude=['audit', 'secure'],
            force=True,
            timeout=600,
            dest='/tmp/test.qkview',
            only_create_file=False
        )
        p = Parameters(params=args)

        # Verify all transformations
        self.assertEqual(p.filename, 'test_qkview.qkview')
        self.assertEqual(p.asm_request_log, '-o asm-request-log')
        self.assertEqual(p.max_file_size, '-s 5120')
        self.assertEqual(p.complete_information, '-c')
        self.assertIn('audit', p.exclude)
        self.assertEqual(p.timeout, (6, 100))

    def test_force_false_dest_not_exists(self):
        """Test idempotent behavior with force=False when dest doesn't exist"""
        set_module_args(dict(
            dest='/tmp/new_qkview.qkview',
            force=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        # POST 1: script create, POST 2: task create (needs _taskId), POST 3: script delete, POST 4: move file, POST 5: delete file
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict()),  # script create
            dict(code=200, contents={'_taskId': 'task123'}),  # task create (needs _taskId)
            dict(code=200, contents=dict()),  # script delete
            dict(code=200, contents=dict()),  # move file
            dict(code=200, contents=dict())   # delete file
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=dict()))  # task exec
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents={'_taskState': 'COMPLETED'})  # task complete
        ])

        # Mock os.path.exists with side_effect for multiple calls
        # Call 1: dest check for force (False - file doesn't exist)
        # Call 2: dirname check (True - dir exists)
        # Call 3: post-download check (True - download succeeded)
        # Call 4: Any extra calls
        with patch.object(bigip_qkview.os.path, 'exists', Mock(side_effect=[False, True, True, True])):
            results = tm.exec_module()

        self.assertFalse(results['changed'])

    def test_force_true_dest_exists(self):
        """Test idempotent behavior with force=True when dest exists"""
        set_module_args(dict(
            dest='/tmp/existing_qkview.qkview',
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_cli_script_status.json')),
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=load_fixture('load_cli_task_start.json')))
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict()),
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        with patch.object(bigip_qkview.os.path, 'exists', Mock(return_value=True)):
            results = tm.exec_module()

        self.assertFalse(results['changed'])

    def test_only_create_file_true(self):
        """Test only_create_file=True skips dest validation and download"""
        set_module_args(dict(
            only_create_file=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        # With only_create_file=True, execute() skips move/download/delete
        # POST 1: script create, POST 2: task create (needs _taskId), POST 3: script delete
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict()),  # script create
            dict(code=200, contents={'_taskId': 'task123'}),  # task create (needs _taskId)
            dict(code=200, contents=dict())   # script delete
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=dict()))
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        results = tm.exec_module()

        self.assertFalse(results['changed'])
        # Verify that only_create_file path was taken (3 post calls: script create, task create, script delete, no move/delete)
        self.assertEqual(tm.client.post.call_count, 3)

    def test_bulk_location_manager_full_flow(self):
        """Test BulkLocationManager end-to-end flow"""
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        bm = BulkLocationManager(module=module, client=Mock())
        bm.client.plugin = Mock()
        bm.client.plugin.download_file = Mock()
        bm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_cli_script_status.json')),
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        bm.client.put = Mock(return_value=dict(code=202, contents=load_fixture('load_cli_task_start.json')))
        bm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict()),
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        results = bm.exec_module()

        self.assertFalse(results['changed'])
        self.assertTrue(bm.client.put.call_count == 1)
        self.assertTrue(bm.client.get.call_count == 2)

    def test_task_completes_on_first_poll(self):
        """Test task completion on first poll attempt"""
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_cli_script_status.json')),
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=load_fixture('load_cli_task_start.json')))
        # Task completes on first get
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        results = tm.exec_module()

        self.assertFalse(results['changed'])
        # Should only call get once since task completed immediately
        self.assertEqual(tm.client.get.call_count, 1)

    def test_filename_edge_cases(self):
        """Test filename with dots and underscores"""
        for filename in ['test_qkview.qkview', 'my.qkview.file', 'test_file_123.qkview']:
            args = dict(filename=filename)
            p = Parameters(params=args)

            # Should not raise error for valid filenames
            self.assertEqual(p.filename, filename)

    def test_download_failure_file_not_saved(self):
        """Test error when download fails to save file locally"""
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock(return_value=None)
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict()),  # script create
            dict(code=200, contents={'_taskId': 'task123'}),  # task create (needs _taskId)
            dict(code=200, contents=dict()),  # script delete
            dict(code=200, contents=dict()),  # move file
            dict(code=200, contents=dict())   # delete file (will fail before this)
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=dict()))
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        # Mock os.path.exists with side_effect for multiple calls
        # Call 1: dest check for force (False - file doesn't exist)
        # Call 2: dirname check (True - dir exists)
        # Call 3: post-download check (False - download failed)
        # Call 4: Any extra calls
        with patch.object(bigip_qkview.os.path, 'exists', Mock(side_effect=[False, True, False, False])):
            with self.assertRaises(F5ModuleError) as err:
                tm.exec_module()

        self.assertIn('Failed to save the qkview to local disk', err.exception.args[0])

    def test_task_failed_state(self):
        """Test error handling when task reaches FAILED state"""
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_cli_script_status.json')),
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        tm.client.put = Mock(return_value=dict(code=202, contents=load_fixture('load_cli_task_start.json')))
        # Task fails immediately
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents={'_taskState': 'FAILED'})
        ])

        with self.assertRaises(F5ModuleError) as err:
            tm.exec_module()

        self.assertIn('qkview creation task failed unexpectedly', err.exception.args[0])

    def test_invalid_exclude_option(self):
        """Test error when invalid exclude option provided"""
        set_module_args(dict(
            dest='/tmp/foo.qkview',
            exclude=['invalid_option']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())

        with self.assertRaises(F5ModuleError) as err:
            tm.present()

        self.assertIn('The specified excludes must be in the following list', err.exception.args[0])

    def test_dest_directory_not_exists(self):
        """Test error when dest directory doesn't exist"""
        set_module_args(dict(
            dest='/nonexistent/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())

        with patch.object(bigip_qkview.os.path, 'exists', Mock(return_value=False)):
            with self.assertRaises(F5ModuleError) as err:
                tm.present()

        self.assertIn("The directory of your 'dest' file does not exist", err.exception.args[0])

    def test_execute_on_device_failure(self):
        """Test error when execute_on_device fails"""
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.execute_on_device = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            tm.execute()

        self.assertIn('Failed to create qkview on device', err.exception.args[0])

    def test_create_script_then_update_flow(self):
        """Test script creation fails with 409, then update succeeds"""
        set_module_args(dict(
            dest='/tmp/foo.qkview'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = MadmLocationManager(module=module, client=Mock())
        tm.client.plugin = Mock()
        tm.client.plugin.download_file = Mock()
        tm.client.post = Mock(side_effect=[
            dict(code=409, contents=dict()),  # Script create returns conflict
            dict(code=200, contents=load_fixture('start_cli_script.json')),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict()),
            dict(code=200, contents=dict())
        ])
        tm.client.put = Mock(side_effect=[
            dict(code=200, contents=dict()),  # Script update succeeds
            dict(code=202, contents=load_fixture('load_cli_task_start.json'))
        ])
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict()),
            dict(code=200, contents={'_taskState': 'COMPLETED'})
        ])

        results = tm.exec_module()

        self.assertFalse(results['changed'])
        # Verify both create POST attempt and update PUT were called
        self.assertTrue(tm.client.post.call_count == 5)
        self.assertTrue(tm.client.put.call_count == 2)
