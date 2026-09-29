# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
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
            ucs="/root/bigip.localhost.localdomain.ucs",
            force=True,
            include_chassis_level_config=True,
            no_license=True,
            no_platform_check=True,
            passphrase="foobar",
            reset_trust=True,
            state='installed'
        )

        p = ModuleParameters(params=args)
        assert p.ucs == '/root/bigip.localhost.localdomain.ucs'
        assert p.force is True
        assert p.include_chassis_level_config is True
        assert p.no_license is True
        assert p.no_platform_check is True
        assert p.passphrase == "foobar"
        assert p.reset_trust is True
        assert p.options == {
            'include-chassis-level-config': True, 'no-license': True,
            'no-platform-check': True, 'passphrase': 'foobar', 'reset-trust': True
        }

    def test_module_parameters_false_ucs_booleans(self):
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            include_chassis_level_config=False,
            no_license=False,
            no_platform_check=False,
            reset_trust=False
        )

        p = ModuleParameters(params=args)
        assert p.ucs == '/root/bigip.localhost.localdomain.ucs'
        assert p.include_chassis_level_config is False
        assert p.no_license is False
        assert p.no_platform_check is False
        assert p.reset_trust is False
        assert p.options == {
            'include-chassis-level-config': False, 'no-license': False,
            'no-platform-check': False, 'reset-trust': False
        }

    def test_module_parameters_no_options(self):
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs"
        )

        p = ModuleParameters(params=args)
        assert p.ucs == '/root/bigip.localhost.localdomain.ucs'
        assert p.options is None


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_ucs_default_present(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[False, True])

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_explicit_present(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[False, True])

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_installed(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value='1638418523586009')
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['task_id'] == '1638418523586009'
        assert results['message'] == 'UCS load async task started with id: 1638418523586009'

    def test_ucs_absent_exists(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.remove_from_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[True, False])

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_absent_fails(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.remove_from_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[True, True])

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Failed to delete' in str(res.exception)


class TestIdempotency(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_ucs_present_idempotent_force_false(self, *args):
        # Test state=present with existing UCS and force=False (idempotent)
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present',
            force=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is False

    def test_ucs_absent_idempotent_not_exists(self, *args):
        # Test state=absent when UCS doesn't exist (idempotent)
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False

    def test_ucs_installed_with_task_id(self, *args):
        # Test state=installed with task_id (checking async task status)
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            task_id='1638418523586009'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=True)
        mm.async_wait = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['message'] == 'UCS loaded successfully'


class TestOptionsHandling(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_ucs_installed_with_reset_trust(self, *args):
        # Test install with reset_trust option
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            reset_trust=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value='1638418523586009')
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['task_id'] == '1638418523586009'

    def test_ucs_installed_with_no_license(self, *args):
        # Test install with no_license option
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            no_license=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value='1638418523586009')
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_installed_with_no_platform_check(self, *args):
        # Test install with no_platform_check option
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            no_platform_check=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value='1638418523586009')
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_installed_with_passphrase(self, *args):
        # Test install with passphrase-encrypted UCS
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            passphrase='MySecretPassphrase123'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value='1638418523586009')
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_installed_with_all_options(self, *args):
        # Test install with all options combined
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            no_license=True,
            no_platform_check=True,
            reset_trust=True,
            passphrase='pass123',
            include_chassis_level_config=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value='1638418523586009')
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True


class TestTimeoutValidation(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()

    def test_timeout_too_low(self):
        # Test timeout below minimum (< 150)
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            timeout=149,
            state='installed'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as res:
            p.timeout
        assert 'Timeout value must be between 150 and 3600' in str(res.exception)

    def test_timeout_too_high(self):
        # Test timeout above maximum (> 3600)
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            timeout=3601,
            state='installed'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as res:
            p.timeout
        assert 'Timeout value must be between 150 and 3600' in str(res.exception)

    def test_timeout_valid_lower_bound(self):
        # Test timeout at lower boundary (150)
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            timeout=150,
            state='installed'
        )

        p = ModuleParameters(params=args)
        delay, divisor = p.timeout
        assert delay == 1.5
        assert divisor == 100

    def test_timeout_valid_upper_bound(self):
        # Test timeout at upper boundary (3600)
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            timeout=3600,
            state='installed'
        )

        p = ModuleParameters(params=args)
        delay, divisor = p.timeout
        assert delay == 36.0
        assert divisor == 100


class TestErrorHandlingAndAsync(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_install_on_device_error_response(self, *args):
        # Test install_on_device with HTTP error
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=400, contents='install error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.install_on_device()
        assert 'install error' in str(res.exception)

    def test_start_task_on_device_error(self, *args):
        # Test _start_task_on_device with HTTP error
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.put = Mock(return_value=dict(code=500, contents='task error'))

        with self.assertRaises(F5ModuleError) as res:
            mm._start_task_on_device('task123')
        assert 'task error' in str(res.exception)

    def test_check_task_exists_error(self, *args):
        # Test check_task_exists_on_device with error response
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='check error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.check_task_exists_on_device('task123')
        assert 'check error' in str(res.exception)

    def test_check_task_exists_404(self, *args):
        # Test check_task_exists_on_device when task doesn't exist (404)
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))

        result = mm.check_task_exists_on_device('task123')
        assert result is False

    def test_async_wait_config_reload_failed(self, *args):
        # Test async_wait when config reload fails on device
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.check_task_exists_on_device = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=200,
            contents={'commandResult': 'Last Configuration Load Status base-config-load-failed'}
        ))

        with self.assertRaises(F5ModuleError) as res:
            mm.async_wait('task123')
        assert 'Failed to reload the configuration' in str(res.exception)

    def test_async_wait_config_reload_success(self, *args):
        # Test async_wait when config reload succeeds
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.check_task_exists_on_device = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=200,
            contents={'commandResult': 'Last Configuration Load Status full-config-load-succeed'}
        ))

        result = mm.async_wait('task123')
        assert result is True

    def test_async_wait_timeout_no_task(self, *args):
        # Test async_wait timeout when task doesn't exist
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.check_task_exists_on_device = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(
            code=200,
            contents={'commandResult': 'no status info'}
        ))

        with self.assertRaises(F5ModuleError) as res:
            mm.async_wait('task123')
        assert 'Module timeout reached' in str(res.exception)

    def test_async_wait_task_completed(self, *args):
        # Test async_wait when task completes
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.check_task_exists_on_device = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'_taskState': 'COMPLETED'}
        ))

        result = mm.async_wait('task123')
        assert result is True

    def test_async_wait_task_failed(self, *args):
        # Test async_wait when task fails
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.check_task_exists_on_device = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'_taskState': 'FAILED'}
        ))

        with self.assertRaises(F5ModuleError) as res:
            mm.async_wait('task123')
        assert 'UCS load task has failed' in str(res.exception)

    def test_async_wait_task_timeout(self, *args):
        # Test async_wait timeout with active task
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.check_task_exists_on_device = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'_taskState': 'RUNNING'}
        ))

        with self.assertRaises(F5ModuleError) as res:
            mm.async_wait('task123')
        assert 'Module timeout reached' in str(res.exception)

    def test_read_current_from_device_error(self, *args):
        # Test read_current_from_device with HTTP error
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='read error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.read_current_from_device()
        assert 'read error' in str(res.exception)

    def test_device_is_ready_timeout(self, *args):
        # Test device_is_ready timeout
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed',
            timeout=150
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='not ready'))

        with self.assertRaises(F5ModuleError) as res:
            mm.device_is_ready()
        assert 'Module timeout reached' in str(res.exception)

    def test_create_on_device_error(self, *args):
        # Test create_on_device with POST error
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.upload_file_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=400, contents='move error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.create_on_device()
        assert 'move error' in str(res.exception)

    def test_remove_from_device_error(self, *args):
        # Test remove_from_device with error
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=400, contents='delete error'))

        with self.assertRaises(F5ModuleError) as res:
            mm.remove_from_device()
        assert 'delete error' in str(res.exception)

    def test_upload_file_to_device_error(self, *args):
        # Test upload_file_to_device with upload error
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.plugin = Mock()
        mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError('upload failed'))

        with self.assertRaises(F5ModuleError) as res:
            mm.upload_file_to_device('/test/file.ucs', 'file.ucs')
        assert 'Failed to upload the file' in str(res.exception)

    def test_check_mode_present(self, *args):
        # Test check mode with state=present
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        module.check_mode = True

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_check_mode_absent(self, *args):
        # Test check mode with state=absent
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        module.check_mode = True

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
