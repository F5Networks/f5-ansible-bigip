# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_ssl_csr
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_csr import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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
            name='ssl_csr_1',
            common_name='ssl_csr_1',
            key_name='ssl_key_1',
            dest='/tmp/ssl_csr_1'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'ssl_csr_1'
        assert p.common_name == 'ssl_csr_1'
        assert p.key_name == 'ssl_key_1'
        assert p.dest == '/tmp/ssl_csr_1'

    def test_api_parameters(self):
        args = load_fixture('load_sys_crypto_csr.json')
        p = ApiParameters(params=args)
        assert p.name == 'ssl_csr_1'
        assert p.common_name == 'ssl_csr_1'


class TestModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_csr.send_teem')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_csr.tmos_version')
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_csr.F5Client')
        self.p4 = patch('os.path.exists')
        self.m4 = self.p4.start()
        self.m4.return_value = True
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.m2 = self.p2.start()
        self.m2.return_value = '14.1.0'
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

    def test_create_csr_success(self, *args):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='b4',
            key_name='default.key',
            dest='/foo/ssl_csr_1',
            province='foobar',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.plugin.download_file = Mock()
        mm.client.post.side_effect = [
            {'code': 200, 'contents': {}},
            {'code': 200, 'contents': {}},
            {'code': 200, 'contents': {}},
            {'code': 200, 'contents': load_fixture('csr_file_does_not_exist.json')},
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['common_name'], 'b4')

    def test_remove_csr_success(self, *args):
        set_module_args(dict(
            name='ssl_csr_1',
            dest='/tmp/ssl_csr_1',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigip_ssl_csr, 'Connection')
    @patch.object(bigip_ssl_csr.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='ssl_csr_1',
            key_name='ssl_key_1',
            dest='/tmp/ssl_csr_1',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_ssl_csr.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_ssl_csr, 'Connection')
    @patch.object(bigip_ssl_csr.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='ssl_csr_1',
            key_name='ssl_key_1',
            dest='/tmp/ssl_csr_1',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_ssl_csr.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(bigip_ssl_csr, 'HAS_PACKAGING', False)
    @patch.object(bigip_ssl_csr, 'Connection')
    @patch.object(bigip_ssl_csr.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_import_error(self, *args):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='ssl_csr_1',
            key_name='ssl_key_1',
            dest='/tmp/ssl_csr_1',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_ssl_csr.PACKAGING_IMPORT_ERROR = "failed to import the 'packaging' package"
            bigip_ssl_csr.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn(
            'Failed to import the required Python library (packaging)',
            result.exception.args[0]['msg']
        )

    def test_execute_errors(self):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='b4',
            key_name='default.key',
            dest='/tmp/ssl_csr_1',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.want.force = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err1:
            mm.create = Mock(return_value=False)
            mm.execute()

        self.assertIn('Failed to create csr on device', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.create = Mock(return_value=True)
            mm._move_csr_to_download = Mock(return_value=False)
            mm.execute()

        self.assertIn('Failed to move the csr file to a downloadable location', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.create = Mock(return_value=True)
            mm._move_csr_to_download = Mock(return_value=True)
            mm._download_file = Mock(return_value=False)
            mm.execute()

        self.assertIn('Failed to save the csr file to local disk', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.create = Mock(return_value=True)
            mm._move_csr_to_download = Mock(return_value=True)
            mm._download_file = Mock(return_value=True)
            mm._delete_csr = Mock(return_value=True)
            mm.file_exists = Mock(return_value=True)
            mm.execute()

        self.assertIn('Failed to remove the remote csr file', err4.exception.args[0])

    def test_on_device_methods(self):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='b4',
            key_name='default.key',
            dest='/tmp/ssl_csr_1',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents={}),
            dict(code=404, contents={}),
            dict(code=401, contents={'unauthorized'})
        ]

        self.assertTrue(mm.exists())
        self.assertFalse(mm.exists())

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()

        self.assertIn("unauthorized", err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.client.post.return_value = dict(code=401, contents={'unauthorized'})
            mm.create_on_device()

        self.assertIn("unauthorized", err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.client.delete.return_value = dict(code=401, contents={'unauthorized'})
            mm.remove_from_device()

        self.assertIn("unauthorized", err3.exception.args[0])

        mm.client.post.side_effect = [
            dict(code=404, contents={}),
            dict(code=401, contents='unauthorized'),
            dict(code=200, contents=load_fixture('csr_file_exists.json')),
            dict(code=200, contents={}),
        ]

        self.assertFalse(mm.file_exists())

        with self.assertRaises(F5ModuleError) as err4:
            mm.file_exists()

        self.assertIn("unauthorized", err4.exception.args[0])

        self.assertTrue(mm.file_exists())
        self.assertFalse(mm.file_exists())

        mm.client.plugin.download_file = Mock()

        self.m4.return_value = False
        self.assertFalse(mm._download_file())

        mm.client.post.side_effect = [
            dict(code=404, contents={}),
            dict(code=401, contents='unauthorized'),
            dict(code=403, contents='forbidden'),
        ]

        self.assertFalse(mm._delete_csr())

        with self.assertRaises(F5ModuleError) as err5:
            mm._delete_csr()

        self.assertIn("unauthorized", err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm._move_csr_to_download()

        self.assertIn("forbidden", err6.exception.args[0])

    def test_remaining_methods(self):
        set_module_args(dict(
            name='ssl_csr_1',
            common_name='b4',
            key_name='default.key',
            dest='/tmp/ssl_csr_1',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        self.m4 = self.p4.start()

        with self.assertRaises(F5ModuleError) as err1:
            self.m4.return_value = False
            mm.present()
        self.assertIn("The directory of your 'dest' file does not exist", err1.exception.args[0])

        self.m4.return_value = True
        mm.exists = Mock(return_value=True)
        self.assertFalse(mm.present())

        with self.assertRaises(F5ModuleError) as err2:
            self.m2.return_value = '13.1.0'
            mm.exec_module()

        self.assertIn('This module requires TMOS version 14.x and above', err2.exception.args[0])

        mm.exists = Mock(return_value=False)
        self.assertFalse(mm.absent())

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.exists = Mock(return_value=True)
            mm.remove()

        self.assertIn('Failed to delete the resourc', err2.exception.args[0])
