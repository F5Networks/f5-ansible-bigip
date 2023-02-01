# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_utility_license_assignment
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_utility_license_assignment import (
    ArgumentSpec, ModuleManager, ModuleParameters
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
    def test_module_parameters_none_values(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=False,
            device_username=None,
            device_password=None,
            device_port=None
        )

        p = ModuleParameters(params=args)

        self.assertIsNone(p.device_username)
        self.assertIsNone(p.device_password)
        self.assertIsNone(p.device_port)

    def test_module_parameters_device_options(self):
        args1 = dict(device='1.1.1.1')
        args2 = dict(device='fake_device_name')
        args3 = dict(device='123e4567-e89b-12d3-a456-426614174000')
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)
        p3 = ModuleParameters(params=args3)

        self.assertTrue(p1.device_is_address)
        self.assertFalse(p1.device_is_id)
        self.assertFalse(p1.device_is_name)

        self.assertFalse(p2.device_is_address)
        self.assertFalse(p2.device_is_id)
        self.assertTrue(p2.device_is_name)

        self.assertFalse(p3.device_is_address)
        self.assertTrue(p3.device_is_id)
        self.assertFalse(p3.device_is_name)

    def test_module_parameters_unmanaged(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=False,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.offering, 'asdf')
        self.assertEqual(p.key, 'XXXX-XXXX-XXXX-XXXX-XXXX')
        self.assertEqual(p.device, '1.1.1.1')
        self.assertFalse(p.managed)
        self.assertEqual(p.device_username, 'admin')
        self.assertEqual(p.device_password, 'secret')
        self.assertEqual(p.device_port, 8443)

    def test_module_parameters_offering_id(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=False,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )

        p = ModuleParameters(params=args)
        p.client = Mock()
        p.client.get.side_effect = [
            {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': 'offering_id'}]}},
            {'code': 200, 'contents': {'totalItems': 0}},
            {'code': 503, 'contents': 'service not available'}
        ]

        self.assertEqual(p.offering_id, 'offering_id')

        with self.assertRaises(F5ModuleError) as err1:
            p.offering_id

        self.assertIn(
            'No offering with the specified name was found.',
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            p.offering_id

        self.assertIn('service not available', err2.exception.args[0])

    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'offering_id', Mock(return_value='fake_id'))
    def test_module_parameter_member_id_error(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )
        m = ModuleParameters(params=args)
        m.client = Mock()

        with patch.object(bigiq_utility_license_assignment.ModuleParameters,
                          'device_is_address', True):

            m.client.get.side_effect = [
                {'code': 200, 'contents': {'totalItems': 0}},
                {'code': 503, 'contents': 'service not available'}
            ]

            self.assertIsNone(m.member_id)

            with self.assertRaises(F5ModuleError) as err1:
                m.member_id

            self.assertIn('service not available', err1.exception.args[0])

    def test_module_parameters_member_id(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=False,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )

        uuid = '123e4567-e89b-12d3-a456-426614174000'
        m = ModuleParameters(params=args)
        m.client = Mock()

        with patch.object(bigiq_utility_license_assignment.ModuleParameters,
                          'device_is_address', True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            self.assertEqual(uuid, m.member_id)

        with patch.multiple(bigiq_utility_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            self.assertEqual(uuid, m.member_id)

        with patch.multiple(bigiq_utility_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=True):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            self.assertEqual(uuid, m.member_id)

        with patch.multiple(bigiq_utility_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=False):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'id': uuid}]}}
            with self.assertRaises(F5ModuleError) as err:
                m.member_id

            self.assertIn(f"Unknown device format '{m.device}'", err.exception.args[0])

    def test_module_parameter_device_reference_error(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )
        m = ModuleParameters(params=args)
        m.client = Mock()

        with patch.object(bigiq_utility_license_assignment.ModuleParameters,
                          'device_is_address', True):

            m.client.get.side_effect = [
                {'code': 200, 'contents': {'totalItems': 0}},
                {'code': 503, 'contents': 'service not available'}
            ]

            with self.assertRaises(F5ModuleError) as err1:
                m.device_reference

            self.assertIn(
                'No device with the specified address was found.',
                err1.exception.args[0]
            )

            with self.assertRaises(F5ModuleError) as err2:
                m.device_reference

            self.assertIn('service not available', err2.exception.args[0])

    def test_module_parameters_device_reference(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )

        uuid = '123e4567-e89b-12d3-a456-426614174000'
        m = ModuleParameters(params=args)
        m.client = Mock()

        with patch.object(bigiq_utility_license_assignment.ModuleParameters,
                          'device_is_address', True):

            expected = dict(
                link='https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices/{0}'.format(uuid)
            )
            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            self.assertEqual(expected, m.device_reference)

        with patch.multiple(bigiq_utility_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=True):

            expected = dict(
                link='https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices/{0}'.format(uuid)
            )
            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            self.assertEqual(expected, m.device_reference)

        with patch.multiple(bigiq_utility_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=True):

            expected = dict(
                link='https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices/{0}'.format(uuid)
            )
            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            self.assertEqual(expected, m.device_reference)

        with patch.multiple(bigiq_utility_license_assignment.ModuleParameters,
                            device_is_address=False, device_is_name=False,
                            device_is_id=False):

            m.client.get.return_value = {'code': 200, 'contents': {'totalItems': 1, 'items': [{'uuid': uuid}]}}
            with self.assertRaises(F5ModuleError) as err:
                m.device_reference

            self.assertIn(f"Unknown device format '{m.device}'", err.exception.args[0])

    def test_module_parameters_managed(self):
        args = dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.offering, 'asdf')
        self.assertEqual(p.key, 'XXXX-XXXX-XXXX-XXXX-XXXX')
        self.assertEqual(p.device, '1.1.1.1')
        self.assertTrue(p.managed)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_utility_license_assignment.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_utility_license_assignment.F5Client')
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

    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'offering_id', Mock(return_value='offering_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'member_id', Mock(return_value='member_id'))
    def test_create(self, *args):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        )
        )

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
        mm.client.post.return_value = {'code': 202}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'offering_id', Mock(return_value='offering_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'member_id', Mock(return_value='member_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'device_username', None)
    def test_create_no_username_error(self, *args):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "You must specify a 'device_username' when working with unmanaged devices.",
            err.exception.args[0]
        )

    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'offering_id', Mock(return_value='offering_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'member_id', Mock(return_value='member_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'device_password', None)
    def test_create_no_password_error(self, *args):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "You must specify a 'device_password' when working with unmanaged devices.",
            err.exception.args[0]
        )

    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'offering_id', Mock(return_value='offering_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'member_id', Mock(return_value='member_id'))
    def test_remove(self, *args):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='absent'
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[True, False])

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigiq_utility_license_assignment, 'Connection')
    @patch.object(bigiq_utility_license_assignment.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        )
        )

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_utility_license_assignment.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_utility_license_assignment, 'Connection')
    @patch.object(bigiq_utility_license_assignment.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        )
        )

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_utility_license_assignment.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'offering_id', Mock(return_value='offering_id'))
    @patch.object(bigiq_utility_license_assignment.ModuleParameters,
                  'member_id', Mock(return_value='member_id'))
    def test_device_call_functions(self):
        set_module_args(dict(
            offering='asdf',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 200},
            {'code': 404},
            {'code': 503, 'contents': 'service not available'},
            {'code': 503, 'contents': 'service not available'}
        ]
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        res1 = mm.present()
        self.assertFalse(res1)

        res2 = mm.absent()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()

        self.assertIn('service not available', err1.exception.args[0])

        with patch.object(mm.want, 'member_id', None):
            res3 = mm.exists()
            self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.create_on_device()

        self.assertIn('service not available', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.wait_for_device_to_be_licensed()

        self.assertIn('service not available', err3.exception.args[0])

        mm.exists = Mock(side_effect=[True, False])

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove()

        self.assertIn(
            'Failed to delete the resource.',
            err4.exception.args[0]
        )

        mm.create_on_device = Mock()
        with self.assertRaises(F5ModuleError) as err4:
            mm.create()

        self.assertIn(
            'Failed to license the remote device.',
            err4.exception.args[0]
        )
