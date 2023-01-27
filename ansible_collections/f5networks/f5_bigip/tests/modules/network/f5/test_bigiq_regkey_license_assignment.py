# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_regkey_license_assignment
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license_assignment import (
    ArgumentSpec, ModuleManager, ModuleParameters, UsableChanges
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
    def test_module_parameters_unmanaged(self):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=False,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )

        p = ModuleParameters(params=args)
        assert p.pool == 'foo-pool'
        assert p.key == 'XXXX-XXXX-XXXX-XXXX-XXXX'
        assert p.device == '1.1.1.1'
        assert p.managed is False
        assert p.device_username == 'admin'
        assert p.device_password == 'secret'
        assert p.device_port == 8443

    def test_module_parameters_None_values(self):
        args = dict(device='fake_device')
        p = ModuleParameters(params=args)

        self.assertIsNone(p.device_password)
        self.assertIsNone(p.device_username)
        self.assertIsNone(p.device_port)
        self.assertFalse(p.device_is_address)

    def test_module_parameters_device_is_id(self):
        args1 = dict(device='123e4567-e89b-12d3-a456-426614174000')
        p1 = ModuleParameters(params=args1)
        args2 = dict(device='$%^&**%$##@')
        p2 = ModuleParameters(params=args2)
        self.assertTrue(p1.device_is_id)
        self.assertFalse(p2.device_is_id)

    def test_module_parameters_device_is_name(self):
        args1 = dict(device='fake_device')
        p1 = ModuleParameters(params=args1)
        args2 = dict(device='1.1.1.1')
        p2 = ModuleParameters(params=args2)
        self.assertTrue(p1.device_is_name)
        self.assertFalse(p2.device_is_name)

    def test_module_parameters_managed(self):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
        )

        p = ModuleParameters(params=args)
        assert p.pool == 'foo-pool'
        assert p.key == 'XXXX-XXXX-XXXX-XXXX-XXXX'
        assert p.device == '1.1.1.1'
        assert p.managed is True

    def test_module_parameters_device_reference(self, *args):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
        )

        m = ModuleParameters(params=args)
        m.client = Mock()

        uuid = '123e4567-e89b-12d3-a456-426614174000'
        expect = dict(
            link=f'https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices/{uuid}'
        )

        with patch.object(bigiq_regkey_license_assignment.ModuleParameters,
                          'device_is_address', True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            device_ref = m.device_reference
            self.assertDictEqual(expect, device_ref)

        with patch.multiple(bigiq_regkey_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            device_ref = m.device_reference
            self.assertDictEqual(expect, device_ref)

        with patch.multiple(bigiq_regkey_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            device_ref = m.device_reference
            self.assertDictEqual(expect, device_ref)

        with patch.multiple(bigiq_regkey_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=False):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            with self.assertRaises(F5ModuleError) as err:
                m.device_reference

            self.assertIn(f"Unknown device format '{m.device}'", err.exception.args[0])

        m.client.get.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'totalItems': 0}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            m.device_reference

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            m.device_reference

        self.assertIn(
            'No device with the specified address was found.',
            err2.exception.args[0]
        )

    def test_module_parameters_pool_id(self):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
        )

        uuid = '123e4567-e89b-12d3-a456-426614174000'
        m = ModuleParameters(params=args)
        m.client = Mock()
        m.client.get.side_effect = [
            {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}},
            {'code': 200, 'contents': {'totalItems': 0, 'items': [{'id': uuid}]}},
            {'code': 500, 'contents': 'service not available'}
        ]
        pool_id = m.pool_id
        self.assertEqual(pool_id, uuid)

        with self.assertRaises(F5ModuleError) as err1:
            m.pool_id

        self.assertIn(
            "No pool with the specified name was found.",
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            m.pool_id

        self.assertIn(
            'service not available',
            err2.exception.args[0]
        )

    def test_module_parameters_member_id(self):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
        )

        uuid = '123e4567-e89b-12d3-a456-426614174000'
        m = ModuleParameters(params=args)
        m.client = Mock()

        with patch.object(bigiq_regkey_license_assignment.ModuleParameters,
                          'device_is_address', True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            self.assertEqual(uuid, m.member_id)

        with patch.multiple(bigiq_regkey_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            self.assertEqual(uuid, m.member_id)

        with patch.multiple(bigiq_regkey_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            self.assertEqual(uuid, m.member_id)

        with patch.multiple(bigiq_regkey_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=False):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            with self.assertRaises(F5ModuleError) as err:
                m.member_id

            self.assertIn(f"Unknown device format '{m.device}'", err.exception.args[0])

        with patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', 'pool_id'):
            m.client.get.side_effect = [
                {'code': 503, 'contents': 'service not available'},
                {'code': 200, 'contents': {'totalItems': 0}}
            ]
            with self.assertRaises(F5ModuleError) as err1:
                m.member_id

            self.assertIn('service not available', err1.exception.args[0])

            mid = m.member_id
            self.assertIsNone(mid)

    def test_usable_changes_parameters(self):
        p1 = UsableChanges(params=dict(managed='yes'))
        p2 = UsableChanges(params=dict(managed=True, device_reference='fake_device'))
        self.assertIsNone(p1.device_port)
        self.assertIsNone(p1.device_username)
        self.assertIsNone(p1.device_password)
        self.assertIsNone(p1.device_address)
        self.assertEqual('fake_device', p2.device_reference)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license_assignment.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license_assignment.F5Client')
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

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', Mock())
    def test_create(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 404},
            {'code': 200},
            {'code': 200, 'contents': {'status': 'LICENSING'}},
            {'code': 200, 'contents': {'status': 'LICENSED'}},
            {'code': 200, 'contents': {'status': 'LICENSED'}},
            {'code': 200, 'contents': {'status': 'LICENSED'}}
        ]
        mm.client.post.side_effect = [{'code': 200}]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 6)

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', Mock())
    def test_remove(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
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
        self.assertEqual(mm.client.get.call_count, 2)
        self.assertEqual(mm.client.delete.call_count, 1)

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', None)
    def test_exists_return_false(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.create = Mock(return_value=True)
        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', Mock())
    def test_exists_response_status_failure(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_create_username_password_exception(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock()
        with patch.object(bigiq_regkey_license_assignment.ModuleParameters,
                          'device_username', None):
            with self.assertRaises(F5ModuleError) as err:
                mm.exec_module()

            self.assertIn(
                "You must specify a 'device_username' when working with unmanaged devices.",
                err.exception.args[0]
            )

        with patch.object(bigiq_regkey_license_assignment.ModuleParameters,
                          'device_password', None):
            with self.assertRaises(F5ModuleError) as err:
                mm.exec_module()

            self.assertIn(
                "You must specify a 'device_password' when working with unmanaged devices.",
                err.exception.args[0]
            )

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Failed to license the remote device.",
            err.exception.args[0]
        )

    def test_present_return_false(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_absent_return_false(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        results = mm.exec_module()

        self.assertFalse(results['changed'])

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', Mock())
    def test_create_on_device_response_failure(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', Mock())
    def test_remove_failed_to_delete(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm._set_changed_options = Mock()
        mm.remove_from_device = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn("Failed to delete the resource.", err.exception.args[0])

    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'pool_id', Mock())
    @patch.object(bigiq_regkey_license_assignment.ModuleParameters, 'member_id', Mock())
    def test_wait_for_device_failure(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[False, True])
        mm.create_on_device = Mock(return_value=True)
        mm.client.get.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigiq_regkey_license_assignment, 'Connection')
    @patch.object(bigiq_regkey_license_assignment.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_regkey_license_assignment.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_regkey_license_assignment, 'Connection')
    @patch.object(bigiq_regkey_license_assignment.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_regkey_license_assignment.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
