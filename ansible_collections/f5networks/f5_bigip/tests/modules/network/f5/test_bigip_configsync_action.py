# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_configsync_action
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_configsync_action import (
    Parameters, ModuleManager, ArgumentSpec, ModuleParameters
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import MagicMock, Mock, patch
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
            sync_device_to_group=True,
            sync_group_to_device=True,
            overwrite_config=True,
            device_group="foo"
        )
        p = Parameters(params=args)
        self.assertTrue(p.sync_device_to_group)
        self.assertTrue(p.sync_group_to_device)
        self.assertTrue(p.overwrite_config)
        self.assertEqual(p.device_group, 'foo')

    def test_module_parameters_yes_no(self):
        args = dict(
            sync_device_to_group='yes',
            sync_group_to_device='no',
            overwrite_config='yes',
            device_group="foo"
        )
        p = Parameters(params=args)
        self.assertEqual(p.sync_device_to_group, 'yes')
        self.assertEqual(p.sync_group_to_device, 'no')
        self.assertEqual(p.overwrite_config, 'yes')
        self.assertEqual(p.device_group, 'foo')

    def test_module_parameters_values(self):
        args = dict(
            sync_device_to_group='no',
            sync_group_to_device='no',
            overwrite_config='yes'
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.sync_device_to_group, False)
        self.assertEqual(p.sync_group_to_device, False)
        self.assertEqual(p.force_full_push, 'force-full-load-push')
        self.assertEqual(p.overwrite_config, True)


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_configsync_action.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_configsync_action.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_update_agent_status_traps(self, *args):
        set_module_args(dict(
            sync_device_to_group='yes',
            device_group="foo"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            {'code': 200, 'contents': ''},
            {'code': 200, 'contents': {'entries': {'http://localhost': {'nestedStats': {'entries': {'status': {'description': 'Standalone'}}}}}}},
            {'code': 200, 'contents': {'entries': {'http://localhost': {'nestedStats': {'entries': {'status': {'description': 'Changes Pending'}}}}}}},
            {'code': 200, 'contents': {'entries': {'http://localhost': {'nestedStats': {'entries': {'status': {'description': 'Changes Pending'}}}}}}},
            {'code': 200, 'contents': {'entries': {'http://localhost': {'nestedStats': {'entries': {'status': {'description': 'Changes Pending'}}}}}}},
            {'code': 200, 'contents': {'entries': {'http://localhost': {'nestedStats': {'entries': {'status': {'description': 'Not All Devices Synced'}}}}}}},
            {'code': 200, 'contents': {'entries': {'http://localhost': {'nestedStats': {'entries': {'status': {'description': 'In Sync'}}}}}}}
        ]
        mm.client.post.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 7)
        self.assertEqual(mm.client.post.call_count, 1)

    def test_device_group_prerequisites_failure(self, *args):
        set_module_args(dict(
            sync_group_to_device='yes',
            device_group="foo"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [{'code': 404}, {'code': 200}]
        mm._get_status_from_resource = Mock(return_value='Awaiting Initial Sync')

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn("The specified 'device_group' does not exist.", err1.exception.args[0])
        self.assertIn(
            "This device group needs an initial sync. Please use "
            "'sync_device_to_group'",
            err2.exception.args[0]
        )

    def test_device_in_sync_already(self, *args):
        set_module_args(dict(
            sync_group_to_device='yes',
            device_group="foo"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm._device_group_exists = Mock(return_value=True)
        mm._sync_to_group_required = Mock(return_value=False)
        mm._get_status_from_resource = Mock(return_value='In Sync')
        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_device_group_exist_exception(self, *args):
        set_module_args(dict(
            sync_group_to_device='yes',
            device_group="foo"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        mm.client.get.return_value = {'code': 503, 'contents': 'Service to check device status is not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Service to check device status is not available', err.exception.args[0])

    def test_execute_on_device_exception(self, *args):
        set_module_args(dict(
            sync_group_to_device='yes',
            device_group="foo"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        mm._device_group_exists = Mock(return_value=True)
        mm._sync_to_group_required = Mock(return_value=False)
        mm.exists = Mock(return_value=False)
        mm._get_status_from_resource = Mock(side_effect=['Disconnected', 'device is in unexpected state'])
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'Unable to execute config-sync on device'},
            {'code': 200},
            {'code': 200}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err3:
            mm.exec_module()

        self.assertIn('Unable to execute config-sync on device', err1.exception.args[0])
        self.assertIn(
            "One or more devices are unreachable (disconnected). "
            "Resolve any communication problems before attempting to sync.",
            err2.exception.args[0]
        )
        self.assertIn('device is in unexpected state', err3.exception.args[0])

    def test_read_device_exception(self, *args):
        set_module_args(dict(
            sync_group_to_device='yes',
            device_group="foo"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )

        mm = ModuleManager(module=module)
        mm._device_group_exists = Mock(return_value=True)
        mm.client.get.return_value = {'code': 503, 'contents': 'Unable to check sync status on device'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Unable to check sync status on device', err.exception.args[0])

    @patch.object(bigip_configsync_action, 'HAS_OBJPATH', False)
    def test_get_details_from_resource_failure(self, * args):
        set_module_args(dict(
            sync_group_to_device='yes',
            device_group='foo'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )

        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value={'entries': {}})

        with self.assertRaises(F5ModuleError) as err:
            mm._get_details_from_resource()

        self.assertIn(
            'objectpath module required, install objectpath module to continue.',
            err.exception.args[0]
        )

    @patch.object(bigip_configsync_action, 'HAS_OBJPATH', False)
    @patch.object(bigip_configsync_action, 'Connection')
    @patch.object(bigip_configsync_action.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_object_path_missing(self, *args):
        set_module_args(dict(
            sync_device_to_group='yes',
            device_group="foo"
        )
        )

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_configsync_action.HAS_OBJPATH_IMPORT_ERROR = "Failed to import the objectpath package."
            bigip_configsync_action.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn(
            'Failed to import the required Python library (objectpath)',
            result.exception.args[0]['msg']
        )

    @patch.object(bigip_configsync_action, 'Connection')
    @patch.object(bigip_configsync_action.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            sync_device_to_group='yes',
            device_group="foo"
        )
        )

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_configsync_action.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_configsync_action, 'Connection')
    @patch.object(bigip_configsync_action.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            sync_device_to_group='yes',
            device_group="foo"
        )
        )

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_configsync_action.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
