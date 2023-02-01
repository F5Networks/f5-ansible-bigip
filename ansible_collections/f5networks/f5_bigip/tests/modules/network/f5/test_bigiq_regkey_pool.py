# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_regkey_pool
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_pool import (
    ArgumentSpec, ModuleManager, ModuleParameters, ApiParameters
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
            description='this is a description'
        )

        p = ModuleParameters(params=args)
        assert p.description == 'this is a description'

    def test_module_parameters_uuid(self):
        args = dict(name='foo')
        uuid = '123e4567-e89b-12d3-a456-426614174000'
        p = ModuleParameters(params=args)
        p.client = Mock()
        p.client.get.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'items': [{'id': uuid, 'name': 'foo'}]}}
        ]

        with self.assertRaises(F5ModuleError) as err:
            p.uuid

        self.assertIn('service not available', err.exception.args[0])

        self.assertEqual(uuid, p.uuid)

    def test_api_parameters(self):
        args = load_fixture('load_regkey_license_pool.json')

        p = ApiParameters(params=args)
        self.assertEqual(p.description, 'this is a description')

    def test_api_parameters_uuid(self):
        args = load_fixture('load_regkey_license_pool.json')
        p = ApiParameters(params=args)
        self.assertEqual(p.uuid, args['id'])


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_pool.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_pool.F5Client')
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

    @patch.object(bigiq_regkey_pool.ModuleParameters, 'uuid', 'none')
    def test_create(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get.return_value = {'code': 404}
        mm.client.post.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigiq_regkey_pool.ModuleParameters, 'uuid', 'none')
    def test_update(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 200},
            {'code': 200, 'contents': {}}
        ]
        mm.client.patch.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigiq_regkey_pool.ModuleParameters, 'uuid', 'none')
    def test_absent(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_exists_response_status_failure(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {}},
            {'code': 503, 'contents': 'service not available'}
        ]

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_create_on_device_response_failure(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_pool.ModuleParameters, 'uuid', 'none')
    def test_update_on_device_response_failure(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock()
        mm.client.patch.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_pool.ModuleParameters, 'uuid', 'none')
    def test_read_from_device_response_failure(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_pool.ModuleParameters, 'uuid', 'none')
    def test_remove_from_device_response_failure(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_failed_to_delete_error(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_update_return_false(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock
        mm.should_update = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_should_update_return_false(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock()
        mm._update_changed_options = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_absent_return_false(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    @patch.object(bigiq_regkey_pool, 'Connection')
    @patch.object(bigiq_regkey_pool.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_regkey_pool.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_regkey_pool, 'Connection')
    @patch.object(bigiq_regkey_pool.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foo',
            description='bar baz',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_regkey_pool.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
