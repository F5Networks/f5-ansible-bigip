# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_ssl_key_cert
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_key_cert import (
    ApiParameters, ModuleParameters, ModuleManager, ArgumentSpec
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
    def test_module_parameters_key(self):
        key_content = load_fixture('create_insecure_key1')
        args = dict(
            key_content=key_content,
            key_name="cert1",
            partition="Common",
            state="present",
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.key_name, 'cert1')
        self.assertEqual(p.key_filename, 'cert1.key')
        self.assertIn('-----BEGIN RSA PRIVATE KEY-----', p.key_content)
        self.assertIn('-----END RSA PRIVATE KEY-----', p.key_content)
        self.assertEqual(p.key_checksum, '91bdddcf0077e2bb2a0258aae2ae3117be392e83')
        self.assertEqual(p.state, 'present')

    def test_module_parameters_cert(self):
        cert_content = load_fixture('create_insecure_cert1')
        args = dict(
            cert_content=cert_content,
            cert_name="cert1",
            partition="Common",
            state="present",
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.cert_name, 'cert1')
        self.assertEqual(p.cert_filename, 'cert1.crt')
        self.assertIn('-----BEGIN CERTIFICATE-----', p.cert_content)
        self.assertIn('-----END CERTIFICATE-----', p.cert_content)
        self.assertIn('Signature Algorithm', p.cert_content)
        self.assertEqual(p.cert_checksum, '1e55aa57ee166a380e756b5aa4a835c5849490fe')
        self.assertEqual(p.state, 'present')

    def test_module_parameters_true_names(self):
        args = dict(
            key_name="key1",
            cert_name="cert1",
            partition="Common",
            state="present",
            issuer_cert='bazbar',
            true_names=True
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.cert_name, 'cert1')
        self.assertEqual(p.cert_filename, 'cert1')
        self.assertEqual(p.key_name, 'key1')
        self.assertEqual(p.key_filename, 'key1')
        self.assertEqual(p.issuer_cert, '/Common/bazbar')
        self.assertEqual(p.key_source_path, 'file:///var/config/rest/downloads/key1_key')
        self.assertEqual(p.cert_source_path, 'file:///var/config/rest/downloads/cert1_cert')

    def test_module_parameters_default_endings(self):
        args = dict(
            key_name="key1.key",
            cert_name="cert1.crt",
            partition="Common",
            state="present",
            issuer_cert='bazbar.crt',
            true_names=False
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.cert_name, 'cert1.crt')
        self.assertEqual(p.cert_filename, 'cert1.crt')
        self.assertEqual(p.key_name, 'key1.key')
        self.assertEqual(p.key_filename, 'key1.key')
        self.assertEqual(p.issuer_cert, '/Common/bazbar.crt')
        self.assertEqual(p.key_source_path, 'file:///var/config/rest/downloads/key1.key')
        self.assertEqual(p.cert_source_path, 'file:///var/config/rest/downloads/cert1.crt')

    def test_module_issuer_cert_key(self):
        args = dict(
            issuer_cert='foo',
            partition="Common",
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.issuer_cert, '/Common/foo.crt')

    def test_api_parameters_none(self):
        p = ApiParameters(params={})

        self.assertIsNone(p.key_filename)
        self.assertIsNone(p.key_source_path)
        self.assertIsNone(p.cert_filename)
        self.assertIsNone(p.cert_source_path)
        self.assertIsNone(p.key_checksum)

        p = ApiParameters(params=dict(key_name='foo', cert_name='bar'))
        self.assertIsNotNone(p.key_filename)
        self.assertIsNone(p.key_source_path)
        self.assertIsNotNone(p.cert_filename)
        self.assertIsNone(p.cert_source_path)


class TestModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_key_cert.send_teem')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ssl_key_cert.F5Client')
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

    def test_import_key_and_cert(self, *args):
        set_module_args(dict(
            key_name='bar_key',
            key_content=load_fixture('create_insecure_key1'),
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            issuer_cert='bar_issuer',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.plugin.upload_file = Mock()
        mm.client.post.side_effect = [
            dict(code=200, contents=dict(transId='1234567')),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents={})
        ]
        mm.client.patch.return_value = dict(code=200, contents={})
        mm.client.put.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['issuer_cert'] == '/Common/bar_issuer.crt')
        self.assertTrue(mm.client.put.called)
        self.assertTrue(mm.client.patch.called)
        self.assertTrue(mm.client.post.call_count == 5)

    def test_import_key_source_path_and_cert_source_path_true_name_true(self, *args):
        set_module_args(dict(
            key_name='bar_key',
            key_content=load_fixture('create_insecure_key1'),
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            issuer_cert='bar_issuer',
            state='present',
            true_names=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.plugin.upload_file = Mock()
        mm.client.post.side_effect = [
            dict(code=200, contents=dict(transId='1234567')),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents={})
        ]
        mm.client.patch.return_value = dict(code=200, contents={})
        mm.client.put.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['key_source_path'] == 'file:///var/config/rest/downloads/bar_key_key')
        self.assertTrue(results['cert_source_path'] == 'file:///var/config/rest/downloads/bar_cert')
        self.assertTrue(mm.client.put.called)
        self.assertTrue(mm.client.patch.called)
        self.assertTrue(mm.client.post.call_count == 5)

    def test_import_key_source_path_and_cert_source_path_true_name_false(self, *args):
        set_module_args(dict(
            key_name='bar_key',
            key_content=load_fixture('create_insecure_key1'),
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            issuer_cert='bar_issuer',
            state='present',
            true_names=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.plugin.upload_file = Mock()
        mm.client.post.side_effect = [
            dict(code=200, contents=dict(transId='1234567')),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents={})
        ]
        mm.client.patch.return_value = dict(code=200, contents={})
        mm.client.put.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['key_source_path'] == 'file:///var/config/rest/downloads/bar_key.key')
        self.assertTrue(results['cert_source_path'] == 'file:///var/config/rest/downloads/bar.crt')
        self.assertTrue(mm.client.put.called)
        self.assertTrue(mm.client.patch.called)
        self.assertTrue(mm.client.post.call_count == 5)

    def test_update_key_and_cert(self, *args):
        set_module_args(dict(
            key_name='bar',
            key_content=load_fixture('create_insecure_key1'),
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.plugin.upload_file = Mock()
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_ssl_key_changed.json')),
            dict(code=200, contents=load_fixture('load_ssl_cert_changed.json'))
        ]
        mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
        mm.client.patch.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['key_checksum'] == '91bdddcf0077e2bb2a0258aae2ae3117be392e83')
        self.assertTrue(results['cert_checksum'] == '1e55aa57ee166a380e756b5aa4a835c5849490fe')
        self.assertTrue(results['key_source_path'] == 'file:///var/config/rest/downloads/bar.key')
        self.assertTrue(results['cert_source_path'] == 'file:///var/config/rest/downloads/bar.crt')

    def test_update_key(self, *args):
        set_module_args(dict(
            key_name='bar',
            key_content=load_fixture('create_insecure_key1'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.plugin.upload_file = Mock()
        mm.client.get.return_value = dict(code=200, contents=load_fixture('load_ssl_key_changed.json'))
        mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
        mm.client.patch.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['key_checksum'] == '91bdddcf0077e2bb2a0258aae2ae3117be392e83')
        self.assertTrue(results['key_source_path'] == 'file:///var/config/rest/downloads/bar.key')

    def test_update_cert(self, *args):
        set_module_args(dict(
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.plugin.upload_file = Mock()
        mm.client.get.return_value = dict(code=200, contents=load_fixture('load_ssl_cert_changed_2.json'))
        mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
        mm.client.patch.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['cert_checksum'] == '1e55aa57ee166a380e756b5aa4a835c5849490fe')
        self.assertTrue(results['cert_source_path'] == 'file:///var/config/rest/downloads/bar.crt')

    def test_update_key_and_cert_content(self, *args):
        set_module_args(dict(
            key_name='bar',
            key_content=load_fixture('create_insecure_key1'),
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.plugin.upload_file = Mock()
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_ssl_key_changed_2.json')),
            dict(code=200, contents=load_fixture('load_ssl_cert_changed_2.json'))
        ]
        mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
        mm.client.patch.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['key_source_path'] == 'file:///var/config/rest/downloads/bar.key')
        self.assertTrue(results['cert_source_path'] == 'file:///var/config/rest/downloads/bar.crt')

    def test_update_key_and_cert_no_change(self, *args):
        set_module_args(dict(
            key_name='bar',
            key_content=load_fixture('create_insecure_key1'),
            cert_name='bar',
            cert_content=load_fixture('create_insecure_cert1'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_ssl_key.json')),
            dict(code=200, contents=load_fixture('load_ssl_cert.json'))
        ]

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertFalse(mm.client.post.called)
        self.assertFalse(mm.client.patch.called)

    def test_remove_key_cert(self, *args):
        set_module_args(dict(
            key_name='bar',
            cert_name='bar',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete.return_value = dict(code=200, contents={})
        mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
        mm.client.patch.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 2)

    @patch.object(bigip_ssl_key_cert, 'Connection')
    @patch.object(bigip_ssl_key_cert.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            key_name='ssl_key_1'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_ssl_key_cert.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_ssl_key_cert, 'Connection')
    @patch.object(bigip_ssl_key_cert.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            key_name='ssl_key_1'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_ssl_key_cert.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_on_device_methods(self, *args):
        set_module_args(dict(
            key_name='bar',
            cert_name='bar'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)

        mm.client.get.return_value = dict(code=404, contents='not found')

        with self.assertRaises(F5ModuleError) as err1:
            mm.read_current_from_device()

        self.assertIn('not found', err1.exception.args[0])

        mm.client.get.side_effect = [
            dict(code=200, contents={}),
            dict(code=404, contents='still not found')
        ]

        with self.assertRaises(F5ModuleError) as err2:
            mm.read_current_from_device()

        self.assertIn('still not found', err2.exception.args[0])

        mm.client.delete.return_value = dict(code=403, contents='forbidden operation')

        with self.assertRaises(F5ModuleError) as err3:
            mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
            mm.client.patch.return_value = dict(code=200, contents={})
            mm.remove_from_device()

        self.assertIn('forbidden operation', err3.exception.args[0])

        mm.client.patch.side_effect = [
            dict(code=401, contents='unauthorized action'),
            dict(code=200, contents={})
        ]
        with self.assertRaises(F5ModuleError) as err4:
            mm.client.post.return_value = dict(code=200, contents=dict(transId='1234567'))
            mm.client.plugin.upload_file = Mock()
            mm.update_on_device()

        self.assertIn('unauthorized action', err4.exception.args[0])

        mm.client.post.side_effect = [
            dict(code=200, contents=dict(transId='1234567')),
            dict(code=500, contents='server error'),
            dict(code=200, contents=dict(transId='1234567')),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=401, contents='unauthorized')
        ]
        mm.client.patch.return_value = dict(code=200, contents={})

        with self.assertRaises(F5ModuleError) as err5:
            mm.client.plugin.upload_file = Mock()
            mm.create_on_device()

        self.assertIn('server error', err5.exception.args[0])

        set_module_args(dict(
            key_name='bar',
            cert_name='bar',
            issuer_cert='foobar'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err6:
            mm.client.put.return_value = dict(code=500, contents='database error')
            mm.client.plugin.upload_file = Mock()
            mm.create_on_device()

        self.assertIn('database error', err6.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            mm.client.plugin.upload_file = Mock(side_effect=F5ModuleError('upload failed'))
            mm.upload_file_to_device('foo', 'bar')

        self.assertIn('Failed to upload the file', err7.exception.args[0])

        mm.client.get.side_effect = [
            dict(code=404, contents='not found'),
            dict(code=401, contents='unauthorized'),
            dict(code=200, contents={}),
            dict(code=404, contents='not found'),
            dict(code=200, contents={}),
            dict(code=401, contents='unauthorized'),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
        ]

        self.assertFalse(mm.exists())

        with self.assertRaises(F5ModuleError) as err8:
            mm.exists()
        self.assertIn('unauthorized', err8.exception.args[0])

        self.assertFalse(mm.exists())

        with self.assertRaises(F5ModuleError) as err9:
            mm.exists()
        self.assertIn('unauthorized', err9.exception.args[0])

        self.assertTrue(mm.exists())

        with self.assertRaises(F5ModuleError) as err10:
            mm.remove_uploaded_file_from_device('foo')

        self.assertIn('unauthorized', err10.exception.args[0])

    def test_remaining_methods(self):
        set_module_args(dict(
            key_name='bar',
            cert_name='bar',
            issuer_cert='foobar'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.remove_from_device = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as err11:
            mm.remove()

        self.assertIn('Failed to delete the resource', err11.exception.args[0])

        self.assertFalse(mm.absent())
