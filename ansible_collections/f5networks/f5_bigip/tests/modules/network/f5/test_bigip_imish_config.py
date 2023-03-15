# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_imish_config
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_imish_config import (
    ModuleManager, ArgumentSpec
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


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_imish_config.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_imish_config.F5Client')
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

    def test_create(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi',
                'neighbor 10.10.10.11 remote-as 65000',
                'neighbor 10.10.10.11 fall-over bfd',
                'neighbor 10.10.10.11 remote-as 65000',
                'neighbor 10.10.10.11 fall-over bfd'
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            after='bfd slow-timer 2000',
            match='exact',
        ))

        current = load_fixture('load_imish_output_1.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if,
            add_file_common_args=self.spec.add_file_common_args
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)

        mm.client.post.side_effect = [
            # read_current_from_device
            {'code': 200, 'contents': {'commandResult': current['commandResult']}},

            # load_config_on_device
            {'code': 200, 'contents': {'commandResult': ''}},

            # remove_uploaded_file_from_device
            {'code': 200}
        ]
        mm.client.plugin.upload_file = Mock()

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.plugin.upload_file.called)
        self.assertEqual(mm.client.post.call_count, 3)

    def test_create_save_when_modified(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi',
                'neighbor 10.10.10.11 remote-as 65000',
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            save_when='modified',
            diff_against='running'
        ))

        current = load_fixture('load_imish_output_1.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if,
            add_file_common_args=self.spec.add_file_common_args
        )

        module._diff = True

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value=current['commandResult'])
        mm.upload_file_to_device = Mock(return_value=True)
        mm.load_config_on_device = Mock(return_value=True)
        mm.remove_uploaded_file_from_device = Mock(return_value=True)

        mm.client.post.return_value = {'code': 200, 'contents': {'commandResult': current['commandResult']}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_save_when_always(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi',
                'neighbor 10.10.10.11 remote-as 65000',
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            save_when='always'
        ))

        current = load_fixture('load_imish_output_1.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if,
            add_file_common_args=self.spec.add_file_common_args
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value=current['commandResult'])
        mm.upload_file_to_device = Mock(return_value=True)
        mm.load_config_on_device = Mock(return_value=True)
        mm.remove_uploaded_file_from_device = Mock(return_value=True)

        mm.client.post.return_value = {'code': 200, 'contents': {'commandResult': current['commandResult']}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_save_when_changed(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi',
                'neighbor 10.10.10.11 remote-as 65000',
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            save_when='changed'
        ))

        current = load_fixture('load_imish_output_1.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if,
            add_file_common_args=self.spec.add_file_common_args
        )

        module._diff = True

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value=current['commandResult'])
        mm.upload_file_to_device = Mock(return_value=True)
        mm.load_config_on_device = Mock(return_value=True)
        mm.remove_uploaded_file_from_device = Mock(return_value=True)

        mm.client.post.return_value = {'code': 200, 'contents': {'commandResult': current['commandResult']}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_diff_against_intended(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi',
                'neighbor 10.10.10.11 remote-as 65000',
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            diff_against='intended',
            intended_config=dict()
        ))

        current = load_fixture('load_imish_output_1.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if,
            add_file_common_args=self.spec.add_file_common_args
        )

        module._diff = True

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value=current['commandResult'])
        mm.upload_file_to_device = Mock(return_value=True)
        mm.load_config_on_device = Mock(return_value=True)
        mm.remove_uploaded_file_from_device = Mock(return_value=True)

        mm.client.post.return_value = {'code': 200, 'contents': {'commandResult': current['commandResult']}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_with_backup(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi',
                'neighbor 10.10.10.11 remote-as 65000',
                'neighbor 10.10.10.11 remote-as 65000',
            ],
            allow_duplicates=True,
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            backup=True,
        ))

        current = load_fixture('load_imish_output_1.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if,
            add_file_common_args=self.spec.add_file_common_args
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.read_current_from_device = Mock(return_value=current['commandResult'])
        mm.upload_file_to_device = Mock(return_value=True)
        mm.load_config_on_device = Mock(return_value=True)
        mm.remove_uploaded_file_from_device = Mock(return_value=True)

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigip_imish_config, 'Connection')
    @patch.object(bigip_imish_config.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi'
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            match='exact',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_imish_config.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_imish_config, 'Connection')
    @patch.object(bigip_imish_config.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            lines=[
                'bgp graceful-restart restart-time 120',
                'redistribute kernel route-map rhi'
            ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            match='exact',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_imish_config.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_call_device_functions(self, *args):
        set_module_args(dict(
            # lines=[
            #     'bgp graceful-restart restart-time 120',
            #     'redistribute kernel route-map rhi'
            # ],
            parents='router bgp 64664',
            before='bfd slow-timer 2000',
            match='exact',
            src="/fake/path/to/src"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.post.side_effect = [
            # remove_uploaded_file_from_device
            {'code': 503, 'contents': 'service not available'},

            # load_config_on_device
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': 'Dynamic routing is not enabled'}},

            # read_current_from_device
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': 'Dynamic routing is not enabled'}},

            # execute_show_commands
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': 'Dynamic routing is not enabled'}},

            # save_on_device
            {'code': 503, 'contents': 'service not available'}
        ]

        res = mm.get_candidate()

        self.assertEqual(res, "/fake/path/to/src")

        with self.assertRaises(F5ModuleError) as err1:
            mm.remove_uploaded_file_from_device('fake_file_name')

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.load_config_on_device(name='fake_name')

        self.assertIn('service not available', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.load_config_on_device(name='fake_name')

        self.assertIn('Dynamic routing is not enabled', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.read_current_from_device()

        self.assertIn('service not available', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.read_current_from_device()

        self.assertIn('Dynamic routing is not enabled', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.execute_show_commands(commands=['tmsh show sys version'])

        self.assertIn('service not available', err6.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            mm.execute_show_commands(commands=['tmsh show sys version'])

        self.assertIn('Dynamic routing is not enabled', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err8:
            mm.save_config(result=dict())

        self.assertIn('service not available', err8.exception.args[0])

        mm.client.plugin.upload_file.side_effect = F5ModuleError()

        with self.assertRaises(F5ModuleError) as err9:
            mm.upload_file_to_device(content='fake_content', name='fake_name')

        self.assertIn('Failed to upload the file.', err9.exception.args[0])
