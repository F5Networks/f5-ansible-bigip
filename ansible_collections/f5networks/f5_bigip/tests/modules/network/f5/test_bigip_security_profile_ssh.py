# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_security_profile_ssh
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_profile_ssh import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import (
    Mock, patch, MagicMock
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
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
            name='test_profile',
            default_action=dict(
                name='foo',
                shell=dict(control='disallow', log=True),
                sub_system=dict(control='disallow', log=True),
                sftp_up=dict(control='disallow', log=True),
                sftp_down=dict(control='disallow', log=True),
                scp_up=dict(control='disallow', log=True),
                scp_down=dict(control='disallow', log=True),
                rexec=dict(control='terminate', log=True),
                forward_local=dict(control='terminate', log=True),
                forward_remote=dict(control='terminate', log=True),
                forward_x11=dict(control='terminate', log=True),
                agent=dict(control='terminate', log=True),
                other=dict(control='terminate', log=True),
            ),
            lang_env_tolerance='any',
            description='this is a new profile',
            timeout=180,
            state='present',
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.default_action_name, 'foo')
        self.assertDictEqual(p.default_action_agent, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_other, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_forward_x11, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_forward_local, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_forward_remote, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_rexec, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_sftp_up, dict(control='disallow', log='yes'))
        self.assertDictEqual(p.default_action_sftp_down, dict(control='disallow', log='yes'))
        self.assertDictEqual(p.default_action_sub_system, dict(control='disallow', log='yes'))
        self.assertDictEqual(p.default_action_shell, dict(control='disallow', log='yes'))
        self.assertEqual(p.lang_env_tolerance, 'any')
        self.assertEqual(p.timeout, 180)
        self.assertEqual(p.description, 'this is a new profile')

    def test_module_parameters_none(self):
        args = dict(name='test_profile')

        p = ModuleParameters(params=args)
        self.assertIsNone(p.default_action_name)
        self.assertIsNone(p.default_action_agent)
        self.assertIsNone(p.default_action_other)
        self.assertIsNone(p.default_action_forward_x11)
        self.assertIsNone(p.default_action_forward_local)
        self.assertIsNone(p.default_action_forward_remote)
        self.assertIsNone(p.default_action_rexec)
        self.assertIsNone(p.default_action_scp_up)
        self.assertIsNone(p.default_action_scp_down)
        self.assertIsNone(p.default_action_sftp_up)
        self.assertIsNone(p.default_action_sftp_down)
        self.assertIsNone(p.default_action_sub_system)
        self.assertIsNone(p.default_action_shell)

    def test_api_parameters(self):
        args = load_fixture('load_ssh_security_profile.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.default_action_name, 'foo')
        self.assertDictEqual(p.default_action_agent, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_other, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_forward_x11, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_forward_local, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_forward_remote, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_rexec, dict(control='terminate', log='yes'))
        self.assertDictEqual(p.default_action_sftp_up, dict(control='disallow', log='yes'))
        self.assertDictEqual(p.default_action_sftp_down, dict(control='disallow', log='yes'))
        self.assertDictEqual(p.default_action_sub_system, dict(control='disallow', log='yes'))
        self.assertDictEqual(p.default_action_shell, dict(control='disallow', log='yes'))
        self.assertEqual(p.lang_env_tolerance, 'any')
        self.assertEqual(p.timeout, 180)
        self.assertEqual(p.description, 'this is a new profile')

    def test_api_parameters_none(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.default_action_name)
        self.assertIsNone(p.default_action_agent)
        self.assertIsNone(p.default_action_other)
        self.assertIsNone(p.default_action_forward_x11)
        self.assertIsNone(p.default_action_forward_local)
        self.assertIsNone(p.default_action_forward_remote)
        self.assertIsNone(p.default_action_rexec)
        self.assertIsNone(p.default_action_scp_up)
        self.assertIsNone(p.default_action_scp_down)
        self.assertIsNone(p.default_action_sftp_up)
        self.assertIsNone(p.default_action_sftp_down)
        self.assertIsNone(p.default_action_sub_system)
        self.assertIsNone(p.default_action_shell)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_profile_ssh.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.velos_partition.F5Client')
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

    def test_create_ssh_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            default_action=dict(
                name='foo',
                shell=dict(control='disallow', log=True),
                sub_system=dict(control='disallow', log=True),
                sftp_up=dict(control='disallow', log=True),
                sftp_down=dict(control='disallow', log=True),
                scp_up=dict(control='disallow', log=True),
                scp_down=dict(control='disallow', log=True),
                rexec=dict(control='terminate', log=True),
                forward_local=dict(control='terminate', log=True),
                forward_remote=dict(control='terminate', log=True),
                forward_x11=dict(control='terminate', log=True),
                agent=dict(control='terminate', log=True),
                other=dict(control='terminate', log=True)
            ),
            lang_env_tolerance='any',
            description='this is a new profile',
            timeout=180,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        expected_action = {'name': 'foo', 'shell': {'control': 'disallow', 'log': 'yes'},
                           'sub_system': {'control': 'disallow', 'log': 'yes'},
                           'sftp_up': {'control': 'disallow', 'log': 'yes'},
                           'sftp_down': {'control': 'disallow', 'log': 'yes'},
                           'scp_up': {'control': 'disallow', 'log': 'yes'},
                           'scp_down': {'control': 'disallow', 'log': 'yes'},
                           'rexec': {'control': 'terminate', 'log': 'yes'},
                           'forward_local': {'control': 'terminate', 'log': 'yes'},
                           'forward_remote': {'control': 'terminate', 'log': 'yes'},
                           'forward_x11': {'control': 'terminate', 'log': 'yes'},
                           'agent': {'control': 'terminate', 'log': 'yes'},
                           'other': {'control': 'terminate', 'log': 'yes'}}

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['default_action'], expected_action)
        self.assertEqual(results['timeout'], 180)
        self.assertEqual(results['description'], 'this is a new profile')
        self.assertEqual(results['lang_env_tolerance'], 'any')

    def test_create_ssh_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            default_action=dict(name='foo')
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_update_ssh_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            default_action=dict(
                name='foo',
                agent=dict(control='allow'),
                other=dict(control='allow')
            ),
            timeout=200
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = dict(agent=dict(control='allow'), other=dict(control='allow'))
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_ssh_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertDictEqual(results['default_action'], expected)
        self.assertEqual(results['timeout'], 200)
        self.assertDictEqual(
            mm.client.patch.call_args_list[0][1]['data']['actions'][0],
            {'agentAction': {'control': 'allow'}, 'otherAction': {'control': 'allow'}, 'name': 'foo'}
        )
        self.assertTrue(results['changed'])

    def test_update_ssh_security_profile_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            default_action=dict(
                name='foo',
                agent=dict(control='terminate')
            )
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_ssh_security_profile.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_ssh_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            default_action=dict(
                name='foo',
                agent=dict(control='allow'),
                other=dict(control='allow')
            ),
            timeout=200
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_ssh_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.patch.called)

    def test_delete_ssh_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_ssh_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, True])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    def test_delete_ssh_security_profile_error_response(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    @patch.object(bigip_security_profile_ssh, 'Connection')
    @patch.object(bigip_security_profile_ssh.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_security_profile_ssh.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_security_profile_ssh, 'Connection')
    @patch.object(bigip_security_profile_ssh.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_security_profile_ssh.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())
