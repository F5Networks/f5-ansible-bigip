# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_software_image
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_image import (
    ApiParameters, ModuleParameters, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import (
    Mock, patch
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


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            filename='/path/to/BIGIP-13.0.0.0.0.1645.iso',
            image='/path/to/BIGIP-13.0.0.0.0.1645.iso',
        )

        p = ModuleParameters(params=args)
        assert p.filename == 'BIGIP-13.0.0.0.0.1645.iso'
        assert p.image == '/path/to/BIGIP-13.0.0.0.0.1645.iso'

    def test_api_parameters(self):
        args = dict(
            file_size='1000 MB',
            build='0.0.3',
            checksum='8cdbd094195fab4b2b47ff4285577b70',
            image_type='release',
            version='13.1.0.8'
        )

        p = ApiParameters(params=args)
        assert p.file_size == 1000
        assert p.build == '0.0.3'
        assert p.checksum == '8cdbd094195fab4b2b47ff4285577b70'
        assert p.image_type == 'release'
        assert p.version == '13.1.0.8'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_image.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_image.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.p3 = patch('time.sleep')
        self.p3.start()
        self.mock_module_helper = patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_upload_iso_image(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.hotfix_exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_sys_software_images.json')),
            dict(code=200, contents=load_fixture('load_sys_software_image.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['image_type'], 'release')
        self.assertEqual(results['version'], '16.1.3.2')
        self.assertEqual(results['build'], '0.0.4')
        self.assertEqual(results['checksum'], 'b155536e421f26277412609742881f1d')
        self.assertEqual(results['file_size'], 2629)

        args, kwargs = mm.client.post.call_args
        self.assertTrue(mm.client.post.call_count == 1)
        self.assertEqual(args[0], '/mgmt/tm/util/bash')
        self.assertDictEqual(
            kwargs['data'],
            {'command': 'run',
             'utilCmdArgs': '-c "chown root:root /shared/images/BIGIP-16.1.3.2-0.0.4.iso;chmod 0644 '
                            '/shared/images/BIGIP-16.1.3.2-0.0.4.iso"'
             }
        )

    def test_upload_hotfix_image(self, *args):
        set_module_args(dict(
            image='/path/to/hotfix-bigip-12.1.1.2.84.204-hf2-ehf84'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.image_exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_sys_software_hotfixes.json')),
            dict(code=200, contents=load_fixture('load_sys_software_hotfix.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['image_type'], 'hotfix')
        self.assertEqual(results['version'], '12.1.1')
        self.assertEqual(results['build'], '2.84.204')
        self.assertEqual(results['checksum'], 'a8239df1e81eda803456cf595e9a2cdf')

        args, kwargs = mm.client.post.call_args
        self.assertTrue(mm.client.post.call_count == 1)
        self.assertEqual(args[0], '/mgmt/tm/util/bash')
        self.assertDictEqual(
            kwargs['data'],
            {'command': 'run',
             'utilCmdArgs': '-c "chown root:root /shared/images/hotfix-bigip-12.1.1.2.84.204-hf2-ehf84;chmod 0644 '
                            '/shared/images/hotfix-bigip-12.1.1.2.84.204-hf2-ehf84"'
             }
        )

    def test_upload_image_raises(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.plugin.upload_file.side_effect = F5ModuleError('Failed to upload image.')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to upload image', err.exception.args[0])
        self.assertTrue(mm.client.plugin.upload_file.called)

    def test_upload_image_resource_not_created(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to create the resource', err.exception.args[0])

    def test_force_update_iso_image(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso',
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.hotfix_exists = Mock(return_value=False)
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_sys_software_images.json')),
            dict(code=200, contents=load_fixture('load_sys_software_images.json')),
            dict(code=200, contents=load_fixture('load_sys_software_image.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 1)
        self.assertEqual(mm.client.delete.call_args[0][0], '/mgmt/tm/sys/software/image/BIGIP-16.1.3.2-0.0.4.iso')

    def test_force_update_hotfix_image(self, *args):
        set_module_args(dict(
            image='/path/to/hotfix-bigip-12.1.1.2.84.204-hf2-ehf84',
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.image_exists = Mock(return_value=False)
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_sys_software_hotfixes.json')),
            dict(code=200, contents=load_fixture('load_sys_software_hotfixes.json')),
            dict(code=200, contents=load_fixture('load_sys_software_hotfix.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 1)
        self.assertEqual(
            mm.client.delete.call_args[0][0], '/mgmt/tm/sys/software/hotfix/hotfix-bigip-12.1.1.2.84.204-hf2-ehf84'
        )

    def test_force_update_image_no_change(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.image_exists = Mock(return_value=True)
        mm.hotfix_exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_image(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.image_exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 1)
        self.assertEqual(mm.client.delete.call_args[0][0], '/mgmt/tm/sys/software/image/BIGIP-16.1.3.2-0.0.4.iso')

    def test_remove_image_no_change(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_image_failed(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-16.1.3.2-0.0.4.iso',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource', err.exception.args[0])

    @patch.object(bigip_software_image, 'Connection')
    @patch.object(bigip_software_image.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-13.0.0.0.0.1645.iso'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_software_image.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_software_image, 'Connection')
    @patch.object(bigip_software_image.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            image='/path/to/BIGIP-13.0.0.0.0.1645.iso'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_software_image.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            image='/path/to/BIGIP-13.0.0.0.0.1645.iso',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=500, contents='server error'))
        mm.client.delete = Mock(return_value=dict(code=401, contents='unauthorized'))
        mm.client.post = Mock(return_value=dict(code=403, contents='forbidden operation'))

        with self.assertRaises(F5ModuleError) as err1:
            mm.image_exists()

        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.hotfix_exists()

        self.assertIn('server error', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()

        self.assertIn('server error', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove_iso_from_device('foobar')

        self.assertIn('unauthorized', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm._set_mode_and_ownership()

        self.assertIn('forbidden operation', err5.exception.args[0])
