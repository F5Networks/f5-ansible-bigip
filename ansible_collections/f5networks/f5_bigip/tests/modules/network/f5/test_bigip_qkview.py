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
