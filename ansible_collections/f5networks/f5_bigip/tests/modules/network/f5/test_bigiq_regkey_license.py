# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_regkey_license

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license import (
    ModuleParameters, ApiParameters, ModuleManager, ArgumentSpec
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
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        )

        p = ModuleParameters(params=args)
        assert p.regkey_pool == 'foo'
        assert p.license_key == 'XXXX-XXXX-XXXX-XXXX-XXXX'
        assert p.accept_eula is True
        assert p.description == 'this is a description'

    def test_module_parameters_regkey_pool_uuid(self):
        uuid = '123e4567-e89b-12d3-a456-426614174000'
        args = dict(regkey_pool_uuid=uuid)
        p1 = ModuleParameters(params=args)

        self.assertEqual(p1.regkey_pool_uuid, uuid)

        p2 = ModuleParameters(params=dict(regkey_pool='fake_regkey_pool'))
        p2.client = Mock()
        p2.client.get.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {}},
            {'code': 200, 'contents': {'items': [{'name': 'fake_regkey_pool', 'id': uuid}]}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            p2.regkey_pool_uuid

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            p2.regkey_pool_uuid

        self.assertIn(
            'Could not find the specified regkey pool.',
            err2.exception.args[0]
        )

        self.assertEqual(p2.regkey_pool_uuid, uuid)

    def test_api_parameters(self):
        args = load_fixture('load_regkey_license_key.json')

        p = ApiParameters(params=args)
        assert p.description == 'foo bar baz'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license.F5Client')
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

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_create(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 404},
            {
                'code': 200,
                'contents': {
                    'status': 'ACTIVATING_AUTOMATIC_NEED_EULA_ACCEPT',
                    'eulaText': 'eulaText'
                }
            },
            {'code': 200, 'contents': {'status': 'READY', 'eulaText': 'eulaText'}}
        ]
        mm.client.post.return_value = {'code': 200}
        mm.client.patch.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['description'], 'this is a description')

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_update(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.client.get.return_value = {'code': 200, 'contents': {}}
        mm.client.patch.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['description'], 'this is a description')

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_absent(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
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

    def test_failed_to_remove_error(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_eula_error(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=False,
            description='this is a description'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'To add a license, you must accept its EULA. '
            'Please see the module documentation for a link to this.',
            err.exception.args[0]
        )

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_create_on_device_failures(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200},
            {'code': 200}
        ]
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'status': 'ACTIVATING_AUTOMATIC_NEED_EULA_ACCEPT', 'eulaText': 'fake eula'}},
            {'code': 200, 'contents': {'status': 'ACTIVATION_FAILED', 'message': 'unable to activate the license'}}
        ]
        mm.client.patch.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('service not available', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.exec_module()

        self.assertIn('unable to activate the license', err3.exception.args[0])

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_exists_response_status_failure(self):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_update_on_device_response_status_failure(self):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock()
        mm.should_update = Mock(return_value=True)

        mm.client.patch.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_remove_from_device_response_status_failure(self):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
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

    @patch.object(bigiq_regkey_license.ModuleParameters, 'regkey_pool_uuid', 'uuid')
    def test_read_from_device_response_status_failure(self):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
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

    def test_update_return_false(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
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
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
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

    @patch.object(bigiq_regkey_license, 'Connection')
    @patch.object(bigiq_regkey_license.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_regkey_license.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_regkey_license, 'Connection')
    @patch.object(bigiq_regkey_license.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            regkey_pool='foo',
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
            description='this is a description'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_regkey_license.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
