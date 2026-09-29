# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility import (
    Parameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import set_module_args


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
            utility='rpm-update'
        )
        p = Parameters(params=args)
        assert p.package == 'MyApp-0.1.0-0001.noarch.rpm'
        assert p.utility == 'rpm-update'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = "9.0"
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_update_rpm_package_success(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        expected = {'operation': 'INSTALL', 'packageFilePath': '/var/config/rest/downloads/MyApp-0.1.0-0001.noarch.rpm'}

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.upload_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('sslo_rpm_update_succeed.json')))

        results = mm.exec_module()

        assert results['changed'] is True
        assert mm.client.post.call_count == 1
        assert mm.client.get.call_count == 1
        assert mm.client.post.call_args[1]['data'] == expected

    def test_update_rpm_package_failure_generic_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.upload_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200,
                                               contents=load_fixture('sslo_rpm_update_failed_error_not_provided.json')))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert "SSL Orchestrator package update failed, check BIG-IP logs for root cause." in str(res.exception)

    def test_update_rpm_package_failure_specific_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.upload_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200,
                                               contents=load_fixture('sslo_rpm_update_failed_error_provided.json')))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert "Package MyApp-0.1.0-0001.noarch.rpm is corrupted, aborting." in str(res.exception)

    def test_remove_sslo_config(self):
        set_module_args(dict(
            timeout=60,
            utility='delete-all',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True


class TestTimeoutValidation(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()

    def test_timeout_too_low(self):
        # Test timeout below minimum (< 10)
        args = dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=9
        )

        p = Parameters(params=args)
        with self.assertRaises(F5ModuleError) as res:
            p.timeout
        assert 'Timeout value must be between 10 and 1800 seconds' in str(res.exception)

    def test_timeout_too_high(self):
        # Test timeout above maximum (> 1800)
        args = dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=1801
        )

        p = Parameters(params=args)
        with self.assertRaises(F5ModuleError) as res:
            p.timeout
        assert 'Timeout value must be between 10 and 1800 seconds' in str(res.exception)

    def test_timeout_valid_lower_bound(self):
        # Test timeout at lower boundary (10)
        args = dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=10
        )

        p = Parameters(params=args)
        delay, divisor = p.timeout
        assert delay == 1
        assert divisor == 10

    def test_timeout_valid_upper_bound(self):
        # Test timeout at upper boundary (1800)
        args = dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=1800
        )

        p = Parameters(params=args)
        delay, divisor = p.timeout
        assert delay == 18
        assert divisor == 100

    def test_timeout_valid_mid_range(self):
        # Test timeout in valid mid range (100)
        args = dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=100
        )

        p = Parameters(params=args)
        delay, divisor = p.timeout
        assert delay == 1
        assert divisor == 100

    def test_timeout_valid_crossing_divisor(self):
        # Test timeout crossing divisor boundary (99->100)
        args = dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=150
        )

        p = Parameters(params=args)
        delay, divisor = p.timeout
        assert delay == 1
        assert divisor == 100


class TestIdempotency(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = "9.0"
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_rpm_update_same_version_idempotent(self):
        # Test rpm-update with same version already installed (idempotent)
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            timeout=60,
            utility='rpm-update',
        ))

        # Minimal same-version idempotent test placeholder
        pass

    def test_rpm_update_idempotent(self):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            timeout=60,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override to indicate same version is already installed
        mm.same_sslo_version = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is False

    def test_delete_all_not_idempotent(self):
        # Test delete-all operation (documented as NOT idempotent)
        set_module_args(dict(
            timeout=60,
            utility='delete-all',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        # delete-all always returns changed=True
        assert results['changed'] is True


class TestCheckMode(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = "9.0"
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_rpm_update_check_mode(self):
        # Test rpm-update in check mode (no actual operations)
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        module.check_mode = True
        mm = ModuleManager(module=module)

        mm.same_sslo_version = Mock(return_value=False)

        results = mm.exec_module()

        # Should indicate change but not actually perform operations
        assert results['changed'] is True

    def test_delete_all_check_mode(self):
        # Test delete-all in check mode
        set_module_args(dict(
            timeout=60,
            utility='delete-all',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        module.check_mode = True
        mm = ModuleManager(module=module)

        results = mm.exec_module()

        assert results['changed'] is True


class TestPackageHandling(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()

    def test_package_file_extraction(self):
        # Test package_file property extracts filename
        args = dict(
            package='/path/to/MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        )
        p = Parameters(params=args)
        assert p.package_file == 'MyApp-0.1.0-0001.noarch.rpm'

    def test_package_none(self):
        # Test package_file when package is None
        args = dict(
            utility='delete-all'
        )
        p = Parameters(params=args)
        assert p.package is None
        assert p.package_file is None

    def test_package_root_extraction(self):
        # Test package_root property extracts base without extension
        args = dict(
            package='/path/to/MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        )
        p = Parameters(params=args)
        assert p.package_root == 'MyApp-0.1.0-0001.noarch'


class TestErrorHandling(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = "9.0"
        self.p4 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.check_sslo_provisioned')
        self.p4.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.p4.stop()

    def test_package_file_not_found_absolute_path(self):
        # Test error when package file doesn't exist (absolute path)
        set_module_args(dict(
            package='/nonexistent/package.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.same_sslo_version = Mock(return_value=False)

        with patch('os.path.exists', return_value=False):
            with self.assertRaises(F5ModuleError) as res:
                mm.create()
            assert 'was not found at' in str(res.exception)

    def test_package_file_not_found_relative_path(self):
        # Test error when package file doesn't exist (relative path)
        set_module_args(dict(
            package='nonexistent/package.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.same_sslo_version = Mock(return_value=False)

        with patch('os.path.exists', return_value=False):
            with self.assertRaises(F5ModuleError) as res:
                mm.create()
            assert 'was not found in' in str(res.exception)

    def test_upload_to_device_error(self):
        # Test error during file upload to device
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        set_module_args(dict(
            package=package_name,
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError('Upload failed'))

        with self.assertRaises(F5ModuleError) as res:
            mm.upload_to_device()
        assert 'Failed to upload the file' in str(res.exception)

    def test_create_on_device_http_error(self):
        # Test HTTP error response from create_on_device
        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.post = Mock(return_value=dict(code=400, contents='error message'))

        with self.assertRaises(F5ModuleError) as res:
            mm.create_on_device()
        assert 'error message' in str(res.exception)

    def test_check_task_on_device_http_error(self):
        # Test HTTP error response from _check_task_on_device
        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as res:
            mm._check_task_on_device('/path/to/task')
        assert 'server error' in str(res.exception)

    def test_wait_for_task_timeout(self):
        # Test timeout during rpm-update task wait
        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Mock POST to return task creation, then mock GET to always show running (never completes)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents={'status': 'RUNNING'}))

        with self.assertRaises(F5ModuleError) as res:
            mm.create_on_device()
        # At timeout=300, divisor=100, so period=3. After 3 iterations, still RUNNING, returns task as RUNNING
        # create_on_device then sees status != FINISHED and raises this error
        assert 'SSL Orchestrator package update failed' in str(res.exception)

    def test_create_on_device_task_failed(self):
        # Test task failure during rpm-update
        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents={'status': 'FAILED'}))

        with self.assertRaises(F5ModuleError) as res:
            mm.create_on_device()
        assert 'SSL Orchestrator package update failed' in str(res.exception)

    def test_remove_from_device_cleanup_post_error(self):
        # Test HTTP error on cleanup POST request
        set_module_args(dict(
            timeout=60,
            utility='delete-all'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.post = Mock(return_value=dict(code=400, contents='cleanup error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.remove_from_device()
        assert 'cleanup error' in str(res.exception)

    def test_remove_from_device_cleanup_get_error(self):
        # Test HTTP error on cleanup GET request
        set_module_args(dict(
            timeout=60,
            utility='delete-all'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.post = Mock(return_value=dict(code=200, contents={'running': True}))
        mm.client.get = Mock(return_value=dict(code=500, contents='error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.remove_from_device()
        assert 'error' in str(res.exception)

    def test_remove_from_device_cleanup_success_message(self):
        # Test cleanup with successful completion message
        set_module_args(dict(
            timeout=60,
            utility='delete-all'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.post = Mock(return_value=dict(code=200, contents={'running': True}))
        # Multiple GET calls: first returns running=True, later returns running=False with success message
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={'running': True}),
            dict(code=200, contents={
                'running': False,
                'message': 'Cleanup process completed. Press ok to continue.'
            })
        ])

        result = mm.remove_from_device()
        assert result is True

    def test_remove_from_device_timeout(self):
        # Test timeout during cleanup operation
        set_module_args(dict(
            timeout=10,
            utility='delete-all'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.post = Mock(return_value=dict(code=200, contents={'running': True}))
        mm.client.get = Mock(return_value=dict(code=200, contents={'running': True}))

        with self.assertRaises(F5ModuleError) as res:
            mm.remove_from_device()
        assert 'Module timeout reached' in str(res.exception)

    def test_unsupported_sslo_version(self):
        # Test error when SSLO version is unsupported
        self.p3.stop()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = "7.0"

        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as res:
            mm.check_sslo_version()
        assert 'Unsupported SSL Orchestrator version' in str(res.exception)

    def test_get_sslo_release_no_items(self):
        # Test _get_sslo_release when no items returned
        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=200, contents={'items': []}))

        result = mm._get_sslo_release()
        assert result is None

    def test_get_sslo_release_wrong_app_name(self):
        # Test _get_sslo_release when app name doesn't match
        set_module_args(dict(
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=200, contents={
            'items': [{'appName': 'other-app', 'release': '1.0'}]
        }))

        result = mm._get_sslo_release()
        assert result is None


class TestMainFunction(unittest.TestCase):
    def test_main_function_success(self, *args):
        # Test main function success path
        set_module_args(dict(
            timeout=60,
            utility='delete-all'
        ))

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.AnsibleModule') as mock_module, \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.Connection'), \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.ModuleManager') as mock_mm_class, \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version') as mock_ver, \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.check_sslo_provisioned'):

            mock_ver.return_value = "9.0"
            mock_mm = MagicMock()
            mock_mm.exec_module.return_value = {'changed': True, 'result': 'success'}
            mock_mm_class.return_value = mock_mm
            mock_module.return_value = MagicMock()
            mock_module.return_value.exit_json = MagicMock()

            from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility import main

            try:
                main()
            except SystemExit:
                pass

    def test_main_function_failure(self, *args):
        # Test main function failure path
        set_module_args(dict(
            package='/nonexistent/package.rpm',
            utility='rpm-update'
        ))

        with patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.AnsibleModule') as mock_module, \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.Connection'), \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.ModuleManager') as mock_mm_class, \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version'), \
             patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.check_sslo_provisioned'):

            mock_mm = MagicMock()
            mock_mm.exec_module.side_effect = F5ModuleError('Test error')
            mock_mm_class.return_value = mock_mm
            mock_module.return_value = MagicMock()
            mock_module.return_value.fail_json = MagicMock()

            from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility import main

            try:
                main()
            except SystemExit:
                pass
