# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_security_profile_ssh_rules
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_profile_ssh_rules import (
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


class TestParameters(unittest.TestCase):
    def test_api_parameters(self):
        args = load_fixture('load_security_profile_ssh_rules.json')

        p = ApiParameters(params=args)

        self.assertDictEqual(p.action_agent, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_forward_local, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_forward_remote, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_forward_x11, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_other, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_rexec, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_scp_down, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_scp_up, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_sftp_down, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_sftp_up, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_shell, dict(control='allow', log='no'))
        self.assertDictEqual(p.action_sub_system, dict(control='allow', log='no'))

        self.assertEqual(p.action_name, 'test_action_name')
        self.assertListEqual(p.users, ["test_user_1"])

    def test_api_parameters_none(self):
        args = dict()

        p = ApiParameters(params=args)

        self.assertIsNone(p.action_name)
        self.assertIsNone(p.action_shell)
        self.assertIsNone(p.action_agent)
        self.assertIsNone(p.action_forward_local)
        self.assertIsNone(p.action_forward_remote)
        self.assertIsNone(p.action_forward_x11)
        self.assertIsNone(p.action_other)
        self.assertIsNone(p.action_rexec)
        self.assertIsNone(p.action_scp_down)
        self.assertIsNone(p.action_scp_up)
        self.assertIsNone(p.action_sftp_down)
        self.assertIsNone(p.action_sftp_up)
        self.assertIsNone(p.action_sub_system)

    def test_module_parameters(self):
        args = dict(
            name='test_rule',
            users=['test_user_1'],
            action=dict(
                name='test_action_name',
                agent=dict(control='allow', log='no'),
                forward_local=dict(control='allow', log='no'),
                forward_remote=dict(control='allow', log='no'),
                forward_x11=dict(control='allow', log='no'),
                other=dict(control='allow', log='no'),
                rexec=dict(control='allow', log='no'),
                scp_down=dict(control='allow', log='no'),
                scp_up=dict(control='allow', log='no'),
                sftp_down=dict(control='allow', log='no'),
                sftp_up=dict(control='allow', log='no'),
                shell=dict(control='allow', log='no'),
                sub_system=dict(control='allow', log='no')
            )
        )

        m = ModuleParameters(params=args)

        self.assertDictEqual(m.action_agent, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_forward_local, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_forward_remote, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_forward_x11, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_other, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_rexec, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_scp_down, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_scp_up, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_sftp_down, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_sftp_up, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_shell, dict(control='allow', log='no'))
        self.assertDictEqual(m.action_sub_system, dict(control='allow', log='no'))

        self.assertEqual(m.action_name, 'test_action_name')
        self.assertListEqual(m.users, ['test_user_1'])

    def test_module_parameters_none(self):
        args = dict()

        p = ModuleParameters(params=args)

        self.assertIsNone(p.action_name)
        self.assertIsNone(p.action_shell)
        self.assertIsNone(p.action_agent)
        self.assertIsNone(p.action_forward_local)
        self.assertIsNone(p.action_forward_remote)
        self.assertIsNone(p.action_forward_x11)
        self.assertIsNone(p.action_other)
        self.assertIsNone(p.action_rexec)
        self.assertIsNone(p.action_scp_down)
        self.assertIsNone(p.action_scp_up)
        self.assertIsNone(p.action_sftp_down)
        self.assertIsNone(p.action_sftp_up)
        self.assertIsNone(p.action_sub_system)

    def test_module_parameters_action_name_none(self):
        args = dict(action=dict())

        m = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            m.action_name

        self.assertIn('action name cannot be None', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_profile_ssh_rules.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_profile_ssh_rules.F5Client')
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

    def test_create_ssh_profile_rule(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='allow', log=True)
                )
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 202},
            {'code': 404},
        ]
        mm.client.post.return_value = {'code': 202}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_ssh_profile_rule_failure(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='allow', log=True)
                )
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 202},
            {'code': 404},
        ]
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_update_ssh_profile_rule(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='terminate', log=True)
                )
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 202},
            {'code': 202},
            {'code': 202, 'contents': load_fixture('load_security_profile_ssh_rules.json')}
        ]
        mm.client.patch.return_value = {'code': 200}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.patch.called)
        self.assertEqual(results['users'], ['test_user_1', 'test_user_2'])
        self.assertEqual(results['action']['shell'], dict(control='terminate', log='yes'))

    def test_update_ssh_profile_rule_no_change(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1']
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 202},
            {'code': 202},
            {'code': 202, 'contents': load_fixture('load_security_profile_ssh_rules.json')}
        ]

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertFalse(mm.client.patch.called)

    def test_update_ssh_profile_rule_failure(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    other=dict(control='terminate', log=True)
                )
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 202},
            {'code': 202},
            {'code': 202, 'contents': load_fixture('load_security_profile_ssh_rules.json')}
        ]
        mm.client.patch.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_delete_ssh_profile_rule(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='terminate', log=True)
                ),
                state='absent'
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.get.return_value = {'code': 202}
        mm.client.delete.return_value = {'code': 202}

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_ssh_profile_rule_response_failure(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='terminate', log=True)
                ),
                state='absent'
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.get.return_value = {'code': 202}
        mm.client.delete.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_delete_ssh_profile_rule_failed_to_delete(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                state='absent'
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, True])
        mm.client.get.return_value = {'code': 202}
        mm.client.delete.return_value = {'code': 202}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(err.exception.args[0], 'Failed to delete the resource.')

    @patch.object(bigip_security_profile_ssh_rules, 'Connection')
    @patch.object(bigip_security_profile_ssh_rules.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='allow', log=True)
                )
            )
        )

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_security_profile_ssh_rules.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_security_profile_ssh_rules, 'Connection')
    @patch.object(bigip_security_profile_ssh_rules.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='allow', log=True)
                )
            )
        )

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_security_profile_ssh_rules.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(
            dict(
                name='test_rule',
                profile_name='test_ssh_profile',
                users=['test_user_1', 'test_user_2'],
                action=dict(
                    name='test_action_name',
                    shell=dict(control='allow', log=True)
                )
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=200), dict(code=200), dict(code=404),
                                          dict(code=200), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied'), dict(code=404),
                                          dict(code=400, contents='server error')])

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

        with self.assertRaises(F5ModuleError) as err4:
            mm.profile_exists()

        self.assertIn(
            f"The profile {mm.want.profile_name} does not exist in {mm.want.partition} partition.",
            err4.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err5:
            mm.profile_exists()

        self.assertIn('server error', err5.exception.args[0])
