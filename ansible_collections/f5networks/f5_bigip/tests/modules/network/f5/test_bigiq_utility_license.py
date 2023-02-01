# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_utility_license
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_utility_license import (
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
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True,
        )

        p = ModuleParameters(params=args)
        assert p.license_key == 'XXXX-XXXX-XXXX-XXXX-XXXX'
        assert p.accept_eula is True


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_utility_license.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_utility_license.F5Client')
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

    def test_create(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'totalItems': 0}},

            # initial license activation
            {'code': 200, 'contents': {'status': 'ACTIVATING_AUTOMATIC_NEED_EULA_ACCEPT', 'selfLink': 'https://selfLink/', 'eulaText': 'fake eula'}},
            {'code': 200, 'contents': {'status': 'READY'}},
            {'code': 200, 'contents': {'status': 'READY'}},
            {'code': 200, 'contents': {'status': 'READY'}},

            # utility license activation
            {'code': 200, 'contents': {'status': 'IN PROGRESS'}},
            {'code': 200, 'contents': {'status': 'READY'}},
            {'code': 200, 'contents': {'status': 'READY'}},
            {'code': 200, 'contents': {'status': 'READY'}},

            {'code': 200, 'contents': {'totalItems': 1}}
        ]
        mm.client.post.return_value = {'code': 200}
        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_create_activation_error(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock()
        mm.wait_for_initial_license_activation = Mock()
        mm.wait_for_utility_license_activation = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to activate the license.', err.exception.args[0])

    def test_create_eula_error(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=False
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
            "To add a license, you must accept its EULA. "
            "Please see the module documentation for a link to this.",
            err.exception.args[0]
        )

    def test_remove(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, True, False, False, False, False])
        mm.client.delete.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_remove_failed_to_delete_error(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, True, False, False, False, True])
        mm.client.delete.return_value = {'code': 200}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    @patch.object(bigiq_utility_license, 'Connection')
    @patch.object(bigiq_utility_license.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_utility_license.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_utility_license, 'Connection')
    @patch.object(bigiq_utility_license.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_utility_license.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            license_key='XXXX-XXXX-XXXX-XXXX-XXXX',
            accept_eula=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'totalItems': 1}},
            {'code': 200, 'contents': {'totalItems': 0}},
            {'code': 503, 'contents': 'service not available'},

            # wait_for_utility_license_activation errors
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'status': 'ACTIVATION_FAILED', 'message': 'failed to activate license'}},

            # wait_for_initial_license_activation errors
            {'code': 200, 'contents': {'status': ''}},
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'status': 'ACTIVATION_FAILED', 'message': 'failed to activate license'}}
        ]

        res1 = mm.present()
        self.assertFalse(res1)

        res2 = mm.absent()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.wait_for_utility_license_activation()

        self.assertIn('service not available', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.wait_for_utility_license_activation()

        self.assertIn('failed to activate license', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.wait_for_initial_license_activation()

        self.assertIn('service not available', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.wait_for_initial_license_activation()

        self.assertIn('failed to activate license', err5.exception.args[0])

        mm.client.delete.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove_from_device()

        self.assertIn('service not available', err6.exception.args[0])

        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err7:
            mm.create_on_device()

        self.assertIn('service not available', err7.exception.args[0])
