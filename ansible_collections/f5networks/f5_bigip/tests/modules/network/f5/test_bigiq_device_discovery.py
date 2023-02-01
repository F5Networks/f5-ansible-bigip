# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_device_discovery

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_discovery import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            device_port=10443,
            ha_name='bazfoo',
            use_bigiq_sync='yes',
            modules=['asm', 'ltm', 'security_shared', 'apm'],
            versioned_conflict_policy='keep_version',
            access_conflict_policy='keep_version',
            access_group_name='access group name',
            device_conflict_policy='keep_version',
            statistics=dict(interval=30, stat_modules=['device', 'ltm'], enable='yes', zone='default')
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.device_address, '192.168.1.1')
        self.assertEqual(p.device_username, 'admin')
        self.assertEqual(p.device_password, 'admin')
        self.assertEqual(p.device_port, 10443)
        self.assertEqual(p.ha_name, 'bazfoo')
        self.assertEqual(p.versioned_conflict_policy, 'KEEP_VERSION')
        self.assertEqual(p.access_conflict_policy, 'KEEP_VERSION')
        self.assertEqual(p.interval, 30)
        self.assertEqual(p.zone, 'default')
        self.assertTrue(p.stats_enabled)
        self.assertTrue(p.use_bigiq_sync)
        self.assertListEqual(p.modules, ['asm', 'adc_core', 'security_shared', 'access'])
        self.assertListEqual(p.stat_modules, [{'module': 'DEVICE'}, {'module': 'LTM'}])

    def test_module_parameters_modules(self):
        args1 = dict(modules=['afm'])
        p1 = ModuleParameters(params=args1)

        with self.assertRaises(F5ModuleError) as err1:
            p1.modules
        self.assertIn(
            "Module 'shared_security' required for 'afm' module.",
            err1.exception.args[0]
        )

        args2 = dict(modules=['asm'])
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err2:
            p2.modules
        self.assertIn(
            "Module 'shared_security' required for 'asm' module.",
            err2.exception.args[0]
        )

        args3 = dict(modules=[])
        p3 = ModuleParameters(params=args3)

        with self.assertRaises(F5ModuleError) as err3:
            p3.modules
        self.assertIn(
            "LTM module must be specified for device discovery and import.",
            err3.exception.args[0]
        )

        args4 = dict(modules=['ltm', 'apm'])
        p4 = ModuleParameters(params=args4)

        with self.assertRaises(F5ModuleError) as err4:
            p4.modules
        self.assertIn(
            "When importing APM 'access_group_name' and 'access_conflict_policy' must be specified.",
            err4.exception.args[0]
        )

    def test_module_parameters_none_values(self):
        args = dict()

        p = ModuleParameters(params=args)

        self.assertIsNone(p.device_password)
        self.assertIsNone(p.device_username)
        self.assertIsNone(p.device_port)
        self.assertIsNone(p.modules)
        self.assertIsNone(p.apm_properties)
        self.assertFalse(p.stats_enabled)

    def test_module_parameters_false_and_errors(self):
        args = dict(
            statistics=dict(enable='no'),
            access_group_first_device='no',
            modules=['apm'],
            device_address='a.b.c.f',
            access_conflict_policy='keep_version',
            access_group_name='access group name'
        )

        p = ModuleParameters(params=args)

        apm_props = {
            'cm:access:conflict-resolution': 'keep_version',
            'cm:access:access-group-name': 'access group name',
            'cm:access:import-shared': False
        }
        self.assertFalse(p.stats_enabled)
        self.assertFalse(p.access_group_first_device)
        self.assertDictEqual(p.apm_properties, apm_props)

        with self.assertRaises(F5ModuleError) as err:
            p.device_address

        self.assertIn(
            'Provided device address: a.b.c.f is not a valid IP.',
            err.exception.args[0]
        )

    def test_api_parameters(self):
        args = load_fixture('load_machine_resolver.json')

        p = ApiParameters(params=args)
        self.assertEqual(sorted(p.modules), sorted(['asm', 'adc_core', 'security_shared']))
        self.assertIsNone(p.access_group_name)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_discovery.bigiq_version')
        self.m1 = self.p1.start()
        self.m1.return_value = '6.1.0'
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_discovery.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_discovery.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.patcher1.stop()
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_create(self, *args):
        set_module_args(dict(
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            versioned_conflict_policy='keep_version',
            modules=['asm', 'ltm', 'security_shared']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm._wait_for_task = Mock(return_value=True)
        mm.reuse_task_on_device = Mock(return_value=True)

        mm.client.get.side_effect = [
            # exists
            {'code': 200, 'contents': {'items': None}},

            # _set_device_id
            {'code': 200, 'contents': {'machineId': 'fake_machine_id'}}
        ]
        mm.client.post.side_effect = [
            # set_trust_with_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}},
        ]
        mm.client.patch.side_effect = [
            # discover_on_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}},

            # import_modules_on_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}},
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 2)
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_update(self, *args):
        set_module_args(dict(
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            modules=['asm', 'ltm', 'security_shared']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.reuse_task_on_device = Mock(return_value=True)
        mm._wait_for_task = Mock(return_value=True)

        mm.client.get.side_effect = [
            # exists
            {'code': 200, 'contents': {'items': [{'machineId': 'fake_machine_id'}]}},

            # read_from_current_device
            {'code': 200, 'contents': {}},
        ]
        mm.client.patch.side_effect = [
            # discover_on_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}},

            # import_modules_on_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}},
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 2)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_remove(self, *args):
        set_module_args(dict(
            device_address='192.168.1.1',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm._wait_for_task = Mock()

        mm.client.post.side_effect = [
            # remove_autority_from_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}},

            # remove_trust_from_device
            {'code': 200, 'contents': {'id': 'fake_task_id'}}
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigiq_device_discovery, 'Connection')
    @patch.object(bigiq_device_discovery.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            modules=['asm', 'ltm', 'security_shared']
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_device_discovery.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_device_discovery, 'Connection')
    @patch.object(bigiq_device_discovery.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            modules=['asm', 'ltm', 'security_shared']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_device_discovery.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(bigiq_device_discovery, 'HAS_PACKAGING', False)
    @patch.object(bigiq_device_discovery, 'Connection')
    @patch.object(bigiq_device_discovery.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_object_path_missing(self, *args):
        set_module_args(dict(
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            modules=['asm', 'ltm', 'security_shared']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_device_discovery.PACKAGING_IMPORT_ERROR = "Failed to import the packaging package."
            bigiq_device_discovery.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn(
            'Failed to import the required Python library (packaging)',
            result.exception.args[0]['msg']
        )

    def test_device_call_functions(self):
        set_module_args(dict(
            device_address='192.168.1.1',
            device_username='admin',
            device_password='admin',
            versioned_conflict_policy='keep_version',
            modules=['asm', 'ltm', 'security_shared']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            # exists
            {'code': 200, 'contents': {}},
            {'code': 503, 'contents': 'service not available'},

            # _set_device_id
            {'code': 503, 'contents': 'service not available'},

            # reuse_task_on_device
            {'code': 200, 'contents': {'items': [1, 2], 'id': 'fake_id'}},
            {'code': 200, 'contents': {'items': [1, 2], 'id': 'fake_id'}},
            {'code': 200, 'contents': {}},
            {'code': 503, 'contents': 'service not available'},

            # read_current_from_device
            {'code': 503, 'contents': 'service not available'},

            # _wait_for_task
            {'code': 200, 'contents': {'status': 'RUNNING'}},
            {'code': 200, 'contents': {'status': 'FINISHED'}},
            {'code': 200, 'contents': {'status': 'CANCELLED'}},
            {'code': 200, 'contents': {'status': 'FAILED'}, 'errorMessage': 'error occurred'},
            {'code': 503, 'contents': 'service not available'},
        ]
        mm.client.post.side_effect = [
            # remove_authority_from_device
            {'code': 503, 'contents': 'service not available'},

            # remove_trust_from_device
            {'code': 503, 'contents': 'service not available'},

            # enable_stats_on_device
            {'code': 200, 'contents': {'id': 'task_id'}},
            {'code': 503, 'contents': 'service not available'},

            # discover_on_device
            {'code': 503, 'contents': 'service not available'},

            # import_modules_on_device
            {'code': 503, 'contents': 'service not available'},

            # set_trust_with_device
            {'code': 503, 'contents': 'service not available'},
        ]

        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm._set_device_id(uri='/')

        self.assertIn('service not available', err2.exception.args[0])

        res2 = mm.reuse_task_on_device(task='discovery')
        res3 = mm.reuse_task_on_device(task='import')
        res4 = mm.reuse_task_on_device(task='import')

        self.assertTrue(res2)
        self.assertTrue(res3)
        self.assertFalse(res4)

        with self.assertRaises(F5ModuleError) as err3:
            mm.reuse_task_on_device(task='import')

        self.assertIn('service not available', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.read_current_from_device()

        self.assertIn('service not available', err4.exception.args[0])

        res5 = mm._wait_for_task(uri='/')
        self.assertTrue(res5)

        with self.assertRaises(F5ModuleError) as err5:
            mm._wait_for_task(uri='/')

        self.assertIn(
            'The task process has been cancelled.',
            err5.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err6:
            mm._wait_for_task(uri='/')

        self.assertIn(
            'error occurred',
            err6.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err6:
            mm._wait_for_task(uri='/')

        self.assertIn(
            'service not available',
            err6.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err7:
            mm.remove_autority_from_device()

        self.assertIn(
            'service not available',
            err7.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err8:
            mm.remove_trust_from_device()

        self.assertIn(
            'service not available',
            err8.exception.args[0]
        )

        mm._wait_for_task = Mock()
        res6 = mm.enable_stats_on_device()
        self.assertTrue(res6)

        with self.assertRaises(F5ModuleError) as err9:
            mm.enable_stats_on_device()

        self.assertIn(
            'service not available',
            err9.exception.args[0]
        )

        mm.reuse_task_on_device = Mock(return_value=False)
        mm.changes = Mock()
        mm.changes.to_return.side_effect = [
            {'modules': ['asm', 'ltm', 'security_shared']},
            {'module_list': ['asm', 'ltm', 'security_shared']}
        ]
        with self.assertRaises(F5ModuleError) as err10:
            mm.discover_on_device()

        self.assertIn(
            'service not available',
            err10.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err11:
            mm.import_modules_on_device()

        self.assertIn(
            'service not available',
            err11.exception.args[0]
        )

        mm.changes.api_params = Mock(return_value=dict())
        with self.assertRaises(F5ModuleError) as err12:
            mm.set_trust_with_device()

        self.assertIn(
            'service not available',
            err12.exception.args[0]
        )

        mm.exists = Mock(return_value=False)
        mm._update_changed_options = Mock(return_value=False)
        res7 = mm.absent()
        res8 = mm.should_update()

        self.assertFalse(res7)
        self.assertFalse(res8)

        with patch.object(bigiq_device_discovery.ModuleParameters, 'modules', None):
            with self.assertRaises(F5ModuleError) as err13:
                mm.create()

            self.assertIn(
                'List of modules cannot be empty if discovering a device.',
                err13.exception.args[0]
            )

        mm.read_current_from_device = Mock()
        mm.should_update = Mock(side_effect=[False, True, True])
        mm.discover_on_device = Mock()
        mm.import_modules_on_device = Mock()
        mm.set_trust_with_device = Mock()
        res9 = mm.update()
        self.assertFalse(res9)

        with patch.object(mm.want, 'force', True):
            res10 = mm.update()
            self.assertTrue(res10)

        with patch.object(bigiq_device_discovery.ModuleParameters, 'stats_enabled', True):
            mm.enable_stats_on_device = Mock()
            res11 = mm.update()
            self.assertTrue(res11)
            self.assertTrue(mm.enable_stats_on_device.call_count, 1)

            res12 = mm.create()
            self.assertTrue(res12)
            self.assertTrue(mm.enable_stats_on_device.call_count, 2)

        version = '1.0.0'

        with self.assertRaises(F5ModuleError) as err14:
            mm.check_bigiq_version(version=version)

        self.assertIn(
            'Module supports only BIGIQ version 6.1.x or higher.',
            err14.exception.args[0]
        )
