# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_apm_policy_import
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_import import (
    ModuleParameters, ModuleManager, ArgumentSpec
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
            name='fake_policy',
            type='access_policy',
            source='/var/fake/fake.tar.gz'
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.name, 'fake_policy')
        self.assertEqual(p.source, '/var/fake/fake.tar.gz')
        self.assertEqual(p.type, 'access_policy')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.policy = os.path.join(fixture_path, 'fake_policy.tar.gz')
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_import.module_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_import.tmos_version')
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_import.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = '14.1.0'
        self.m3 = self.p3.start()
        self.m3.return_value = True
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_import.F5Client')
        self.m4 = self.p4.start()
        self.m4.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.patcher1.stop()
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.m4.stop()
        self.mock_module_helper.stop()

    def test_import_from_file(self, *args):
        set_module_args(dict(
            name='fake_policy',
            source=self.policy,
            type='access_policy',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post.side_effect = [
            {'code': 200, 'contents': {}},
            {'code': 200}
        ]
        mm.client.get.return_value = {'code': 404}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['name'], 'fake_policy')
        self.assertEqual(results['source'], self.policy)

    def test_upload_file_to_device_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            source=self.policy,
            type='access_policy',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to upload the file.', err.exception.args[0])

    def test_policy_import_return_false(self, *args):
        set_module_args(dict(
            name='fake_policy',
            source=self.policy,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.get.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    @patch.object(bigip_apm_policy_import, 'module_provisioned',
                  Mock(return_value=False))
    def test_module_not_provisioned_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            type='access_policy',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'APM must be provisioned to use this module.',
            err.exception.args[0]
        )

    @patch.object(bigip_apm_policy_import, 'tmos_version',
                  Mock(return_value='13.0.0'))
    def test_version_less_than_14_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            type='access_policy',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'Due to bug ID685681 it is not possible to use '
            'this module on TMOS version below 14.x',
            err.exception.args[0]
        )

    @patch.object(bigip_apm_policy_import, 'Connection')
    @patch.object(bigip_apm_policy_import.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_apm_policy_import.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_apm_policy_import, 'Connection')
    @patch.object(bigip_apm_policy_import.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_apm_policy_import.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(bigip_apm_policy_import, 'HAS_PACKAGING', False)
    @patch.object(bigip_apm_policy_import, 'Connection')
    @patch.object(bigip_apm_policy_import.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_import_error(self, *args):
        set_module_args(dict(
            name='foobar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_apm_policy_import.PACKAGING_IMPORT_ERROR = "failed to import the 'packaging' package"
            bigip_apm_policy_import.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn(
            'Failed to import the required Python library (packaging)',
            result.exception.args[0]['msg']
        )

    def test_call_device_functions(self, *args):
        set_module_args(dict(
            name='fake_policy',
            source=self.policy,
            reuse_objects='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}
        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()

        self.assertIn('service not available', err1.exception.args[0])

        mm.upload_file_to_device = Mock()
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': 'command failed'}},
            {'code': 503, 'contents': 'service not available'},
        ]

        with self.assertRaises(F5ModuleError) as err2:
            mm.import_file_to_device()

        self.assertIn('service not available', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.import_file_to_device()

        self.assertIn('command failed', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove_temp_file_from_device()

        self.assertIn('service not available', err4.exception.args[0])
