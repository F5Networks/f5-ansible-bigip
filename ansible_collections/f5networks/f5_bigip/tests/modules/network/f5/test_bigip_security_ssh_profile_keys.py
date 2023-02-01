# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_security_ssh_profile_keys
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_ssh_profile_keys import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import (
    Mock, patch, MagicMock
)
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, fail_json, exit_json, AnsibleExitJson, AnsibleFailJson
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


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_ssh_profile_keys.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_ssh_profile_keys.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_ssh_profile_keys(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            proxy_client_private_key="XXXXXXXXXXXXXXXXXX",
            proxy_client_public_key="YYYYYYYYYYYYYYYYYYY",
            proxy_server_public_key="CCCCCCCCCCCCCCCCCCC",
            proxy_server_private_key="BBBBBBBBBBBBBBBBBB",
            real_server_public_key="AAAAAAAAAAAAAAAAAAAA"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [dict(code=200), dict(code=404)]
        mm.client.post.return_value = dict(code=200)

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_client_public_key'], 'YYYYYYYYYYYYYYYYYYY')
        self.assertEqual(results['proxy_client_private_key'], 'XXXXXXXXXXXXXXXXXX')
        self.assertEqual(results['proxy_server_public_key'], 'CCCCCCCCCCCCCCCCCCC')
        self.assertEqual(results['proxy_server_private_key'], 'BBBBBBBBBBBBBBBBBB')
        self.assertEqual(results['real_server_public_key'], 'AAAAAAAAAAAAAAAAAAAA')
        self.assertTrue(mm.client.post.called)

    def test_create_ssh_profile_keys_failed(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            proxy_client_private_key="XXXXXXXXXXXXXXXXXX",
            proxy_client_public_key="YYYYYYYYYYYYYYYYYYY",
            proxy_server_public_key="CCCCCCCCCCCCCCCCCCC",
            proxy_server_private_key="BBBBBBBBBBBBBBBBBB",
            real_server_public_key="AAAAAAAAAAAAAAAAAAAA"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [dict(code=200), dict(code=404)]
        mm.client.post.return_value = dict(code=503, contents='internal server error')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_update_ssh_profile_keys_force_on(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            proxy_client_private_key="XXXXXXXXXXXXXXXXXX",
            proxy_server_private_key="BBBBBBBBBBBBBBBBBB",
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('load_ssh_profile_keys.json'))
        mm.client.patch.return_value = dict(code=200)

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_client_private_key'], 'XXXXXXXXXXXXXXXXXX')
        self.assertEqual(results['proxy_server_private_key'], 'BBBBBBBBBBBBBBBBBB')
        self.assertTrue(mm.client.patch.called)

    def test_update_ssh_profile_keys_force_off(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            proxy_client_private_key="XXXXXXXXXXXXXXXXXX",
            proxy_server_private_key="BBBBBBBBBBBBBBBBBB",
            force=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('load_ssh_profile_keys.json'))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_ssh_profile_keys(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            proxy_client_private_key="XXXXXXXXXXXXXXXXXX",
            proxy_server_private_key="BBBBBBBBBBBBBBBBBB",
            proxy_client_public_key="YYYYYYYYYYYYYYYYYYY",
            proxy_server_public_key="CCCCCCCCCCCCCCCCCCC",
            real_server_public_key="AAAAAAAAAAAAAAAAAAAA"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('load_ssh_profile_no_keys.json'))
        mm.client.patch.return_value = dict(code=200)

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_client_public_key'], 'YYYYYYYYYYYYYYYYYYY')
        self.assertEqual(results['proxy_client_private_key'], 'XXXXXXXXXXXXXXXXXX')
        self.assertEqual(results['proxy_server_public_key'], 'CCCCCCCCCCCCCCCCCCC')
        self.assertEqual(results['proxy_server_private_key'], 'BBBBBBBBBBBBBBBBBB')
        self.assertEqual(results['real_server_public_key'], 'AAAAAAAAAAAAAAAAAAAA')
        self.assertTrue(mm.client.patch.called)

    def test_update_ssh_profile_keys_failed(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            proxy_client_public_key="YYYYYYYYYYYYYYYYYYY",
            proxy_server_public_key="CCCCCCCCCCCCCCCCCCC",
            real_server_public_key="AAAAAAAAAAAAAAAAAAAA"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('load_ssh_profile_no_keys.json'))
        mm.client.patch.return_value = dict(code=503, contents='internal server error')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])
        self.assertTrue(mm.client.patch.called)

    def test_delete_ssh_profile_keys(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete.return_value = dict(code=200)

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_ssh_profile_keys_failed(self, *args):
        set_module_args(dict(
            name='test_auth',
            profile_name='test_ssh_profile',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete.return_value = dict(code=403, contents='forbidden')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('forbidden', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    @patch.object(bigip_security_ssh_profile_keys, 'Connection')
    @patch.object(bigip_security_ssh_profile_keys.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            profile_name="barfoo",
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_security_ssh_profile_keys.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_security_ssh_profile_keys, 'Connection')
    @patch.object(bigip_security_ssh_profile_keys.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            profile_name="barfoo",
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_security_ssh_profile_keys.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            profile_name="barfoo",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=404), dict(code=403, contents='forbidden'), dict(code=200),
                                          dict(code=404), dict(code=503, contents='internal server error'),
                                          dict(code=401, contents='access denied')])

        with self.assertRaises(F5ModuleError) as err:
            mm.profile_exists()
        self.assertIn('The ssh profile barfoo does not exist in Common partition.', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err1:
            mm.profile_exists()
        self.assertIn('forbidden', err1.exception.args[0])

        mm.profile_exists = Mock(return_value=True)
        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err2:
            mm.exists()
        self.assertIn('internal server error', err2.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err3:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.read_current_from_device()
        self.assertIn('access denied', err4.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())
