# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import ConnectionError

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_software_install
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_install import (
    ApiParameters, ModuleParameters, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, PropertyMock
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
            volume='HD1.2',
            type='standard',
            image='BIGIP-13.0.0.0.0.1645.iso',
            timeout=600,
            volume_uri='/fake/foo/bar'
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.volume, 'HD1.2')
        self.assertEqual(p.image, 'BIGIP-13.0.0.0.0.1645.iso')
        self.assertTupleEqual(p.timeout, (6.0, 100))
        self.assertEqual(p.volume_uri, '/fake/foo/bar')

        p = ModuleParameters(params=dict(timeout=100))

        with self.assertRaises(F5ModuleError) as err:
            p.timeout()
        self.assertIn('Timeout value must be between 150 and 3600 seconds', err.exception.args[0])

    def test_cached_parameters(self):
        args = dict(
            image_info=load_fixture('load_sys_software_image.json'),
            type='standard'
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.build, '0.0.4')
        self.assertEqual(p.version, '16.1.3.2')
        self.assertEqual(p.image_type, 'image')

        args = dict(
            block_device_image_info=load_fixture('load_sys_software_block_image.json'),
            type='vcmp'
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.build, '0.0.3')
        self.assertEqual(p.version, '15.1.8.1')
        self.assertEqual(p.block_device_image_type, 'block-device-image')

        args = dict(
            version='99.1.1',
            build='4.4.4',
            image_type='foobar',
            block_device_image_type='bazbar',
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.version, '99.1.1')
        self.assertEqual(p.build, '4.4.4')
        self.assertEqual(p.image_type, 'foobar')
        self.assertEqual(p.block_device_image_type, 'bazbar')

    def test_module_from_device_methods(self):
        p = ModuleParameters(params=dict(), client=Mock())
        p.client.get = Mock(return_value=dict(code=401, contents='unauthorized'))

        with self.assertRaises(F5ModuleError) as err1:
            p.read_image_from_device('foo')
        self.assertEqual('unauthorized', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            p.read_block_device_image_from_device()
        self.assertEqual('unauthorized', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            p.read_block_device_hotfix_from_device()
        self.assertEqual('unauthorized', err3.exception.args[0])

        p.client.get = Mock(return_value=dict(code=404, contents={}))

        self.assertFalse(p.read_block_device_hotfix_from_device())

    def test_api_from_device_methods(self):
        p = ApiParameters(params=dict(), client=Mock())
        p.client.get = Mock(return_value=dict(code=401, contents='unauthorized'))

        with self.assertRaises(F5ModuleError) as err1:
            p.read_image_from_device('foo')
        self.assertEqual('unauthorized', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            p.read_block_device_image_from_device()
        self.assertEqual('unauthorized', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            p.read_block_device_hotfix_from_device()
        self.assertEqual('unauthorized', err3.exception.args[0])

        p.client.get = Mock(return_value=dict(code=404, contents={}))

        self.assertFalse(p.read_block_device_hotfix_from_device())


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_install.send_teem')
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_software_install.F5Client')
        self.p3 = patch('time.sleep')
        self.p3.start()
        self.m2 = self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_start_software_install(self, *args):
        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2'
        ))

        current = ApiParameters(client=Mock())

        volumes = dict(code=200, contents=load_fixture('load_volumes.json'))
        volume = dict(code=404, contents=dict())
        images = dict(code=200, contents=load_fixture('load_sys_software_images.json'))
        hotfixes = dict(code=404, contents=dict())
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        current.client.get = Mock(side_effect=[images, hotfixes])
        mm.have = current
        mm.client.get = Mock(
            side_effect=[volumes, volume, images, hotfixes]
        )
        mm.client.post = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['message'], 'Started software image installation 13.0.0.iso on volume HD1.2.')
        self.assertEqual(results['volume_uri'], '/mgmt/tm/sys/software/volume/HD1.2')

    def test_start_software_hotfix_install(self, *args):
        set_module_args(dict(
            image='hotfix-bigip-12.1.1.2.84.204-hf2-ehf84',
            volume='HD1.2'
        ))

        current = ApiParameters(client=Mock())

        volumes = dict(code=200, contents=load_fixture('load_volumes.json'))
        volume = dict(code=404, contents=dict())
        images = dict(code=404, contents=dict())
        hotfixes = dict(code=200, contents=load_fixture('load_sys_software_hotfixes.json'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        current.client.get = Mock(side_effect=[images, hotfixes])
        mm.have = current
        mm.client.get = Mock(
            side_effect=[volumes, volume, images, hotfixes]
        )
        mm.client.post = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            results['message'],
            'Started software image installation hotfix-bigip-12.1.1.2.84.204-hf2-ehf84 on volume HD1.2.'
        )
        self.assertEqual(results['volume_uri'], '/mgmt/tm/sys/software/volume/HD1.2')

    def test_start_software_install_fails(self, *args):
        set_module_args(dict(
            image='12.0.0.iso',
            volume='HD1.2'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        current = ApiParameters(client=Mock())
        mm = ModuleManager(module=module)
        current.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sys_software_images.json')))
        mm.have = current
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_volumes.json')),
            dict(code=404, contents=dict())
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertEqual('The specified image was not found on the device.', err.exception.args[0])

    def test_start_software_vcmp_install(self, *args):
        set_module_args(dict(
            block_device_image='BIGIP-15.1.8.1.0.0.3.iso',
            type='vcmp',
            volume='HD1.2'
        ))

        current = ApiParameters(client=Mock())

        volumes = dict(code=200, contents=load_fixture('load_volumes.json'))
        volume = dict(code=404, contents=dict())
        images = dict(code=200, contents=load_fixture('load_sys_software_block_images.json'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        current.client.get = Mock(return_value=images)
        mm.have = current
        mm.client.get = Mock(
            side_effect=[volumes, volume, images]
        )
        mm.client.post = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            results['message'], 'Started block software image installation BIGIP-15.1.8.1.0.0.3.iso on volume HD1.2.'
        )
        self.assertEqual(results['volume_uri'], '/mgmt/tm/sys/software/volume/HD1.2')

    def test_start_software_vcmp_hotfix_install(self, *args):
        set_module_args(dict(
            block_device_image='Hotfix-BIGIP-12.1.2.2.0.276-HF2.iso',
            type='vcmp',
            volume='HD1.2'
        ))

        current = ApiParameters(client=Mock())

        volumes = dict(code=200, contents=load_fixture('load_volumes.json'))
        volume = dict(code=404, contents=dict())
        images = dict(code=404, contents=dict())
        hotfixes = dict(code=200, contents=load_fixture('load_sys_software_block_hotfixes.json'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        current.client.get = Mock(side_effect=[images, hotfixes])
        mm.have = current
        mm.client.get = Mock(
            side_effect=[volumes, volume, images, hotfixes]
        )
        mm.client.post = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            results['message'],
            'Started block software image installation Hotfix-BIGIP-12.1.2.2.0.276-HF2.iso on volume HD1.2.'
        )
        self.assertEqual(results['volume_uri'], '/mgmt/tm/sys/software/volume/HD1.2')

    def test_start_software_vcmp_install_fails(self, *args):
        set_module_args(dict(
            block_device_image='BIGIP-12.1.1.iso',
            type='vcmp',
            volume='HD1.2'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        current = ApiParameters(client=Mock())
        mm = ModuleManager(module=module)
        current.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('load_sys_software_block_images.json'))
        )
        mm.have = current
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_volumes.json')),
            dict(code=404, contents=dict())
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertEqual('The specified block_device_image was not found on the device.', err.exception.args[0])

    def test_software_install_progress_check(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            state='installed',
            timeout=300,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        done = dict(code=200, contents=load_fixture('load_volume_install_complete.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, done]
        )

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['message'], 'Software installation on volume: HD1.2 complete.')

    def test_software_install_activation_progress_check(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        done = dict(code=200, contents=load_fixture('load_volume_install_active.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, done]
        )

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            results['message'], 'Software installation on volume: HD1.2 complete, volume: HD1.2 is now active.'
        )

    def test_software_install_progress_check_device_not_ready(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=False)
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(
            results['message'], 'Device is restarting services, unable to check software installation status.'
        )

    def test_software_install_progress_check_device_restarts(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        error = dict(code=400, contents=dict())

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(side_effect=[True, False])
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, error]
        )
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(
            results['message'], 'Device is restarting services, unable to check software installation status.'
        )

    def test_software_install_fails(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        fail = dict(code=200, contents=load_fixture('load_volume_install_fail.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=True)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, fail]
        )
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        self.assertIn("Software installation on volume: HD1.2 failed.", res.exception.args[0])

    def test_software_install_activation_fails(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        prog_27 = dict(code=200, contents=load_fixture('load_volume_install_27pct.json'))
        prog_75 = dict(code=200, contents=load_fixture('load_volume_install_75pct.json'))
        done = dict(code=200, contents=load_fixture('load_volume_install_complete.json'))

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=True)
        mm.client.get = Mock(
            side_effect=[prog_27, prog_75, done]
        )
        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        self.assertIn("Software installation and activation of volume: HD1.2 failed.", res.exception.args[0])

    def test_software_install_progress_check_media_missing(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        resp = dict(code=200, contents=load_fixture('load_volume_install_media_missing.json'))
        error = dict(code=400, contents=dict())

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(side_effect=[True, False])
        mm.client.get = Mock(
            side_effect=[resp, error]
        )
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(
            results['message'], 'Device is restarting services, unable to check software installation status.'
        )

    def test_software_install_progress_check_media_default(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        resp = dict(code=200, contents=load_fixture('load_volume_install_default.json'))
        error = dict(code=400, contents=dict())

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(side_effect=[True, True, False])
        mm.client.get = Mock(
            side_effect=[error, resp, resp]
        )
        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(
            results['message'], 'Device is restarting services, unable to check software installation status.'
        )

    def test_software_install_progress_timeout(self, *args):
        set_module_args(dict(
            volume_uri='/mgmt/tm/sys/software/volume/HD1.2',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.device_is_ready = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=dict(status='running')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('state change is unknown', err.exception.args[0])

    @patch.object(bigip_software_install, 'Connection')
    @patch.object(bigip_software_install.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_software_install.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_software_install, 'Connection')
    @patch.object(bigip_software_install.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_software_install.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_volume_exists_function(self, *args):
        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2',
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=500, contents='server error'),
            dict(code=200, contents=dict(items=[])),
            dict(code=401, contents='unauthorized'),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.determine_volume_url()

        self.assertIn('server error', err.exception.args[0])

        mm.determine_volume_url()
        self.assertTrue(mm.volume_url, '/mgmt/tm/sys/software/volume/HD1.2')

        mm.determine_volume_url = Mock()
        mm.volume_url = '/mgmt/tm/sys/software/volume/HD1.2'

        with self.assertRaises(F5ModuleError) as err:
            mm.volume_exists()

        self.assertIn('unauthorized', err.exception.args[0])

        mm.client.get = Mock(return_value=dict(code=200, contents=dict(items=[])))

        with patch.object(ModuleParameters, 'version', PropertyMock(return_value='12.1.0')):
            res = mm.volume_exists()

        self.assertFalse(res)

        with patch.object(ModuleParameters, 'version', PropertyMock(return_value=None)), \
                patch.object(ModuleParameters, 'build', PropertyMock(return_value='12.1.0')):
            res = mm.volume_exists()

        self.assertFalse(res)

        with patch.object(ModuleParameters, 'version', PropertyMock(return_value=None)), \
                patch.object(ModuleParameters, 'build', PropertyMock(return_value=None)):
            res = mm.volume_exists()

        self.assertTrue(res)

        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.determine_volume_url = Mock()
        mm.volume_url = '/mgmt/tm/sys/software/volume/HD1.2'

        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(media=[dict(defaultBootLocation=True)])),
            dict(code=200, contents=dict(items=[]))
        ])

        with patch.object(ModuleParameters, 'version', PropertyMock(return_value=None)), \
                patch.object(ModuleParameters, 'build', PropertyMock(return_value=None)):
            res = mm.volume_exists()

        self.assertTrue(res)

        with patch.object(ModuleParameters, 'version', PropertyMock(return_value=None)), \
                patch.object(ModuleParameters, 'build', PropertyMock(return_value=None)):
            res = mm.volume_exists()

        self.assertFalse(res)

    @patch.object(ModuleParameters, 'image_type', PropertyMock(return_value='image'))
    def test_on_device_functions(self, *args):
        set_module_args(dict(
            image='13.0.0.iso',
            volume='HD1.2',
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = ConnectionError('socket reset')

        c1, r1 = mm.check_volume_status()
        self.assertIsNone(r1)
        self.assertEqual(c1, 400)

        res2 = mm.device_is_ready()
        self.assertFalse(res2)

        mm.client.get = Mock(return_value=dict(code=400, contents={}))

        res3 = mm.device_is_ready()
        self.assertFalse(res3)

        mm.client.post = Mock(side_effect=[
            dict(code=500, contents='server error'),
            dict(code=200, contents=dict(commandResult='command failed'))
        ])

        with self.assertRaises(F5ModuleError) as err1:
            mm.update_on_device()

        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.update_on_device()

        self.assertIn('command failed', err2.exception.args[0])

        mm.volume_exists = Mock(return_value=True)
        res4 = mm.present()
        self.assertFalse(res4)
