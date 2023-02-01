# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_lx_package
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_lx_package import (
    Parameters, ArgumentSpec, ModuleManager
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
            package='MyApp-0.1.0-0001.noarch.rpm',
            state='present'
        )
        p = Parameters(params=args)
        self.assertEqual(p.package, 'MyApp-0.1.0-0001.noarch.rpm')

    def test_module_parameters_package(self):
        args1 = dict(package=None)
        args2 = dict(package='fake_package_name')
        p1 = Parameters(params=args1)
        p2 = Parameters(params=args2)

        self.assertIsNone(p1.package)
        self.assertIsNone(p1.package_file)
        self.assertIsNone(p1.package_root)

        p2._module = Mock()
        p2._module.run_command = Mock(return_value=(0, 'fake_package_name', None))

        self.assertEqual(p2.package_name, 'fake_package_name')

    def test_module_parameters_timeout(self, *args):
        args1 = dict(timeout=9)
        args2 = dict(timeout=1801)

        p1 = Parameters(params=args1)
        p2 = Parameters(params=args2)

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


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_lx_package.send_teem')
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_lx_package.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.m3 = self.p3.start()
        self.m3.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_upload_rpm_package(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[False, True])
        mm.wait_for_task = Mock(return_value=dict(status='FINISHED'))

        mm.client.post.side_effect = [
            {'code': 201, 'contents': {'commandResult': ''}},
            {'code': 202, 'contents': {'selfLink': '/task/path'}},
            {'code': 200},
            {'code': 200},
        ]

        results = mm.exec_module()

        self.assertEqual(mm.client.post.call_count, 4)
        self.assertTrue(results['changed'])

    @patch.object(bigip_lx_package.os.path, 'exists', Mock(return_value=True))
    def test_failed_to_install_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            state='present',
            retain_package_file='yes',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.check_file_exists_on_device = Mock(return_value=True)
        mm.create_on_device = Mock()
        mm.enable_iapplx_on_device = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Failed to install LX package.",
            err.exception.args[0]
        )

    def test_remove_rpm_package(self, *args):
        package_file = 'MyApp-0.1.0-0001.noarch.rpm'
        package_name = os.path.join(fixture_path, package_file)

        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        module.run_command = Mock(return_value=(None, None, None))
        mm = ModuleManager(module=module)

        mm.client.post.return_value = {'code': 202, 'contents': {'selfLink': '/task/path'}}
        mm.client.get.side_effect = [
            dict(code=200, contents={'status': 'FINISHED', 'queryResponse': [{'packageName': 'MyApp-0.1.0-0001.noarch.rpm'}]}),
            dict(code=200, contents={'status': 'FINISHED'}),
            dict(code=200, contents={'status': 'FINISHED', 'queryResponse': [{'packageName': ''}]}),
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 3)

    def test_get_installed_packages_failures(self, *args):
        package_file = 'MyApp-0.1.0-0001.noarch.rpm'
        package_name = os.path.join(fixture_path, package_file)

        set_module_args(dict(
            package=package_name
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'selfLink': '/'}}
        ]
        mm.wait_for_task = Mock(return_value={'status': 'FAILED'})

        with self.assertRaises(F5ModuleError) as err1:
            mm.get_installed_packages_on_device()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.get_installed_packages_on_device()

        self.assertIn(
            'Failed to find the installed packages on the device.',
            err2.exception.args[0]
        )

    def test_remove_rpm_response_status_error(self, *args):
        package_file = 'MyApp-0.1.0-0001.noarch.rpm'
        package_name = os.path.join(fixture_path, package_file)

        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigip_lx_package.os.path, 'exists', Mock(return_value=False))
    def test_absolute_package_not_found_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f'The specified LX package was not found at {mm.want.package}.',
            err.exception.args[0]
        )

    @patch.object(bigip_lx_package.os.path, 'exists', Mock(return_value=False))
    def test_relative_package_not_found_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm').strip('/')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with patch.object(bigip_lx_package.os, 'getcwd',
                          Mock(return_value=package_name)):
            with self.assertRaises(F5ModuleError) as err:
                mm.exec_module()

            self.assertIn(
                f'The specified LX package was not found in {mm.want.package}.',
                err.exception.args[0]
            )

    @patch.object(bigip_lx_package.os.path, 'exists', Mock(return_value=False))
    def test_exists(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.get_installed_packages_on_device = Mock(return_value=[{'packageName': mm.want.package_root}])
        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_failure_to_delete_packaged(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post.return_value = {'code': 200, 'contents': {'selfLink': '/'}}
        mm.wait_for_task = Mock(return_value={'status': 'FAILED'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the LX package.', err.exception.args[0])

    def test_wait_for_task_timeout(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        expected = {'status': 'IN PROGRESS'}
        mm = ModuleManager(module=module)
        mm._check_task_on_device = Mock(return_value=expected)
        result = mm.wait_for_task(path='/')

        self.assertEqual(expected, result)

    def test_upload_to_device_failure(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError)

        with self.assertRaises(F5ModuleError) as err:
            mm.upload_to_device()

        self.assertIn("Failed to upload the file.", err.exception.args[0])

    def test_remove_package_from_device_failure(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.remove_package_file_from_device()

        self.assertIn('service not available', err.exception.args[0])

    def test_create_on_device_failures(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'selfLink': '/'}}
        ]
        mm.wait_for_task = Mock(return_value={'status': 'FAILED', 'errorMessage': 'unable to install package on device'})

        with self.assertRaises(F5ModuleError) as err1:
            mm.create_on_device()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.create_on_device()

        self.assertIn('unable to install package on device', err2.exception.args[0])

    def test_enable_iapplx_on_device_failure(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.enable_iapplx_on_device()

        self.assertIn('service not available', err.exception.args[0])

    def test_check_task_on_device(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm._check_task_on_device('/')

        self.assertIn('service not available', err.exception.args[0])

    def test_check_file_exists_on_device(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': mm.want.package_file}}
        ]

        with self.assertRaises(F5ModuleError) as err:
            mm.check_file_exists_on_device()

        self.assertIn('service not available', err.exception.args[0])

        result = mm.check_file_exists_on_device()
        self.assertTrue(result)

    @patch.object(bigip_lx_package, 'Connection')
    @patch.object(bigip_lx_package.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            package='foobar'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_lx_package.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_lx_package, 'Connection')
    @patch.object(bigip_lx_package.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            package='foobar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_lx_package.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
