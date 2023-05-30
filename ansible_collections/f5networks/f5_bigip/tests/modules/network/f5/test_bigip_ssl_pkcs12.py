# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_ssl_pkcs12
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_pkcs12 import (
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
            source='/var/fake/fake.p12',
            cert_pass='nopass'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'fake'
        assert p.source == '/var/fake/fake.p12'
        assert p.filename == 'fake.p12'
        assert p.cert_pass == 'nopass'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_pkcs12.send_teem')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_pkcs12.F5Client')
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

    def test_import_from_file(self, *args):
        set_module_args(dict(
            name='fake_cert',
            source='/var/fake/fake.p12',
            cert_pass='nopass'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.upload_file = Mock()
        mm.client.post.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['name'], 'fake_cert')
        self.assertTrue(results['source'], '/var/fake/fake.p12')
        self.assertTrue(mm.client.post.call_count == 2)

    def test_remove_from_device(self, *args):
        set_module_args(dict(
            name='fake_cert',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 2)

    @patch.object(bigip_ssl_pkcs12, 'Connection')
    @patch.object(bigip_ssl_pkcs12.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='ssl_key_1'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_ssl_pkcs12.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_ssl_pkcs12, 'Connection')
    @patch.object(bigip_ssl_pkcs12.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='ssl_key_1'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_ssl_pkcs12.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_on_device_methods(self):
        set_module_args(dict(
            name='fake_cert',
            force=False,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        mm.client.post.side_effect = [
            dict(code=500, contents='server error'),
            dict(code=401, contents='unauthorized')
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.remove_temp_file_from_device()
        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.install_on_device()
        self.assertIn('unauthorized', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError('upload failed'))
            mm.upload_file_to_device('foo', 'bar')

        self.assertIn('Failed to upload the file', err3.exception.args[0])

        mm.client.delete.side_effect = [
            dict(code=401, contents='unauthorized'),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=404, contents='not found'),
        ]

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove_from_device()
        self.assertIn('unauthorized', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.remove_from_device()
        self.assertIn('not found', err5.exception.args[0])

        mm.client.get.side_effect = [
            dict(code=404, contents='not found'),
            dict(code=200, contents={}),
            dict(code=401, contents='unauthorized'),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=401, contents='unauthorized'),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
        ]

        self.assertFalse(mm.exists())

        with self.assertRaises(F5ModuleError) as err5:
            mm.exists()
        self.assertIn('unauthorized', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.exists()
        self.assertIn('unauthorized', err6.exception.args[0])

        self.assertTrue(mm.exists())

        mm.exists = Mock(side_effect=[True, False, True])
        mm.remove_from_device = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as err7:
            mm.remove()

        self.assertIn('Failed to delete the resource', err7.exception.args[0])

        self.assertFalse(mm.absent())

        self.assertFalse(mm.present())
