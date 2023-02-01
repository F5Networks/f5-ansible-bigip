# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_fast_template
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_template import (
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
    def test_module_parameters(self):
        args = dict(
            name='fake',
            source='/var/fake/fake.zip',
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'fake')
        self.assertEqual(p.source, '/var/fake/fake.zip')

    def test_module_parameters_no_name(self):
        args = dict(
            source='/var/fake/fake.zip',
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'fake')
        self.assertEqual(p.source, '/var/fake/fake.zip')

    def test_module_parameters_purge(self):
        args = dict(
            state='purge'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, None)
        self.assertEqual(p.state, 'purge')


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_template.send_teem')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_template.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_fast_template_set(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_response_status_failure(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip',
            state='present',
            force='yes',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_create_upload_file_failure(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip',
            state='present',
            force='yes',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to upload the file.', err.exception.args[0])

    def test_create_fast_template_set_force_false(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip',
            state='present',
            force='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.return_value = {'code': 404}
        mm.client.post.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['source'], '/var/fake/fake.zip')
        self.assertEqual(results['name'], 'fake')
        self.assertEqual(mm.client.get.call_count, 1)

    def test_remove_temp_file_from_device_failure(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip',
            state='present',
            force='yes',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.create_on_device = Mock(return_value=True)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_remove_fast_template(self, *args):
        set_module_args(dict(
            name='fake',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 200},
            {'code': 404}
        ]
        mm.client.delete.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['name'], 'fake')
        self.assertEqual(mm.client.get.call_count, 2)
        self.assertEqual(mm.client.delete.call_count, 1)

    def test_remove_already_absent_template_set(self, *args):
        set_module_args(dict(
            name='fake',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_response_status_failure(self, *args):
        set_module_args(dict(
            name='fake',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_fail_remove_template(self, *args):
        set_module_args(dict(
            name='fake',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_purge_all_fast_template_sets(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.return_value = {'code': 200, 'contents': True}
        mm.client.delete.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_purge_return_false(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_purge_response_status_failure(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.client.delete.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_exists_response_status_failure(self, * args):
        set_module_args(dict(
            state='purge',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.return_value = {
            'code': 503,
            'contents': 'service not available'
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_exists_return_False(self, * args):
        set_module_args(dict(
            state='purge',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.return_value = {'code': 200, 'contents': False}

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    @patch.object(bigip_fast_template, 'Connection')
    @patch.object(bigip_fast_template.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_fast_template.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_fast_template, 'Connection')
    @patch.object(bigip_fast_template.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_fast_template.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
