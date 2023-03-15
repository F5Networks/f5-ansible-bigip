# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("F5 Ansible modules require Python >= 2.7")

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_command
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_command import (
    Parameters, ModuleManager, V1Manager, V2Manager, BaseManager, ArgumentSpec
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
    with open(path) as f:
        data = f.read()
    try:
        data = json.loads(data)
    except Exception:
        pass
    return data


class TestParameters(unittest.TestCase):

    def test_module_parameters(self):
        args = dict(
            commands=[
                "tmsh show sys version"
            ],
            chdir="/home/user1",
        )
        p = Parameters(params=args)

        self.assertEqual(len(p.commands), 1)
        self.assertEqual(p.chdir, '/home/user1')

    def test_module_parameters_errors(self):
        args1 = dict(commands=None)
        p1 = Parameters(params=args1)

        self.assertListEqual(p1.raw_commands, [])

        args2 = dict(
            commands=[
                "show sys version | cat"
            ]
        )

        p2 = Parameters(params=args2)
        p2.convert_commands_cli = Mock(return_value=[{'command': 'show sys version', 'pipeline': 'cat'}])
        p2.convert_commands = Mock(return_value=[{'command': 'show sys version', 'pipeline': 'cat'}])

        self.assertListEqual(p2.cli_commands, ['tmsh -c "show sys version" | cat'])
        self.assertListEqual(p2.rest_commands, ['tmsh -c \\"show sys version\\" | cat'])

    def test_module_parameters_missing_quotes(self):
        args = dict(
            commands=[
                "\"show sys version"
            ]
        )
        p = Parameters(params=args)

        p.convert_commands_cli = Mock(return_value=[dict(command='"show sys version')])
        p.merge_command_dict_cli = Mock()
        p.convert_commands = Mock(return_value=[dict(command='"show sys version')])
        p.merge_command_dict = Mock()

        with self.assertRaises(Exception) as err1:
            p.cli_commands
        self.assertIn('Double quotes are unbalanced', err1.exception.args[0])

        with self.assertRaises(Exception) as err2:
            p.rest_commands
        self.assertIn('Double quotes are unbalanced', err2.exception.args[0])

    def test_module_parameters_non_tmsh(self):
        args = dict(
            commands=[
                "show sys version"
            ],
            chdir="home/user1",
            is_tmsh=False
        )
        p = Parameters(params=args)

        p.convert_commands_cli = Mock(return_value=[dict(command='show sys version')])
        p.merge_command_dict_cli = Mock()

        p.convert_commands = Mock(return_value=[dict(command='show sys version')])
        p.merge_command_dict = Mock()

        self.assertEqual(len(p.commands), 1)
        self.assertEqual(p.chdir, '/home/user1')
        self.assertListEqual(p.rest_commands, ['tmsh -c \\"cd /home/user1; show sys version\\"'])
        self.assertListEqual(p.cli_commands, ['tmsh -c "cd /home/user1; show sys version"'])


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_command.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_command.F5Client')
        self.m3 = self.p3.start()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_run_single_command(self, *args):
        set_module_args(dict(
            commands=[
                "tmsh show sys version"
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        m1 = V2Manager(module=module)
        m1.execute_on_device = Mock(return_value=['resp1', 'resp2'])

        mm = ModuleManager(module=module)
        mm._run_commands = Mock(return_value=[])
        mm.get_manager = Mock(return_value=m1)

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm._run_commands.call_count, 0)

    def test_run_single_modification_command(self, *args):
        set_module_args(dict(
            commands=[
                "tmsh create ltm virtual foo"
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        m1 = V2Manager(module=module)
        m1.execute_on_device = Mock(return_value=['resp1', 'resp2'])

        mm = ModuleManager(module=module)
        mm._run_commands = Mock(return_value=[])
        mm.get_manager = Mock(return_value=m1)

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm._run_commands.call_count, 0)

    def test_cli_command(self, *args):
        set_module_args(dict(
            commands=[
                "show sys version"
            ],
            use_ssh=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        m1 = V1Manager(module=module)
        m1.execute_on_device = Mock(return_value=['resp1', 'resp2', 'resp3'])

        mm = ModuleManager(module=module)
        mm._run_commands = Mock(return_value=[])
        mm.get_manager = Mock(return_value=m1)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

        # call count is two on CLI transport because we must first
        # determine if the remote CLI is in tmsh mode or advanced shell
        # (bash) mode.
        #
        # 1 call for the shell check
        # 1 call for the command in the "commands" list above
        #
        # Can we change this in the future by making the terminal plugin
        # find this out ahead of time?
        self.assertEqual(m1.execute_on_device.call_count, 3)

    def test_command_with_commas(self, *args):
        set_module_args(dict(
            commands="""
              tmsh create /auth ldap system-auth {bind-dn uid=binduser,
              cn=users,dc=domain,dc=com bind-pw $ENCRYPTEDPW check-roles-group
              enabled search-base-dn cn=users,dc=domain,dc=com servers add {
              ldap.server.com } }
            """
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        m1 = V2Manager(module=module)
        m1.execute_on_device = Mock(return_value=['resp1', 'resp2'])

        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=m1)

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_normalizing_command_show(self, *args):
        args = dict(
            commands=[
                "show sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        assert result[0] == 'show sys version'

    def test_normalizing_command_delete(self, *args):
        args = dict(
            commands=[
                "delete sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'delete sys version')

    def test_normalizing_command_modify(self, *args):
        args = dict(
            commands=[
                "modify sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'modify sys version')

    def test_normalizing_command_list(self, *args):
        args = dict(
            commands=[
                "list sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'list sys version')

    def test_normalizing_command_tmsh_show(self, *args):
        args = dict(
            commands=[
                "tmsh show sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'show sys version')

    def test_normalizing_command_tmsh_delete(self, *args):
        args = dict(
            commands=[
                "tmsh delete sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'delete sys version')

    def test_normalizing_command_tmsh_modify(self, *args):
        args = dict(
            commands=[
                "tmsh modify sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'modify sys version')

    def test_normalizing_command_tmsh_list(self, *args):
        args = dict(
            commands=[
                "tmsh list sys version"
            ],
        )

        result = V2Manager.normalize_commands(args['commands'])

        self.assertEqual(result[0], 'list sys version')

    @patch.object(bigip_command, 'Connection')
    @patch.object(bigip_command.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            commands=[
                "tmsh list sys version"
            ],
        )
        )

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_command.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_command, 'Connection')
    @patch.object(bigip_command.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            commands=[
                "tmsh list sys version"
            ],
        )
        )

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_command.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_call_device_functions(self, *args):
        set_module_args(dict(
            commands=[
                "tmsh list sys version"
            ],
            match='any',
            wait_for="result contains BIGIP",
            use_ssh=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        m1 = V1Manager(module=module)
        m2 = V2Manager(module=module)
        mm = ModuleManager(module=module)
        bm = BaseManager(module=module)

        commands = [
            dict(command="tmsh modify sys version"),
            dict(command="tmsh show sys version"),
        ]

        m2.client.post.side_effect = [
            {'code': 200, 'contents': {'commandResult': 'execution successful'}},
            {'code': 200, 'contents': {'commandResult': 'execution successful'}},
            {'code': 503, 'contents': 'service not available'},
        ]

        res1 = m2.execute_on_device(commands)
        self.assertListEqual(res1, ['execution successful', 'execution successful'])

        with self.assertRaises(F5ModuleError) as err:
            m2.execute_on_device(commands)

        self.assertIn('service not available', err.exception.args[0])

        with patch.object(bigip_command, 'run_commands', Mock(return_value='')):
            res = m1.execute_on_device('cmd')
            self.assertEqual(res, '')

        m1.execute_on_device = Mock(side_effect=[Exception('Syntax Error:'), Exception('Error')])

        res2 = m1.is_tmsh()
        self.assertTrue(res2)

        with self.assertRaises(Exception) as err1:
            m1.is_tmsh()

        self.assertIn('Error', err1.exception.args[0])

        manager_type = mm.get_manager('v1')
        self.assertTrue(isinstance(manager_type, V1Manager))
        manager_type = mm.get_manager('v2')
        self.assertTrue(isinstance(manager_type, V2Manager))

        res3 = m2.determine_change(["The requested vlan already exists"])
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            m2._check_known_errors(['usage: tmsh'])

        self.assertIn(
            "tmsh command printed its 'help' message instead of running your command. "
            "This usually indicates unbalanced quotes.",
            err2.exception.args[0]
        )

        res4 = m2.normalize_commands(raw_commands=None)

        self.assertIsNone(res4)

        param = [
            {'output': 'one-line', 'command': 'list ltm profile html'},
            {'output': 'text', 'command': 'list ltm profile html one-line'}
        ]

        out = [
            {'command': 'list ltm profile html one-line'},
            {'command': 'list ltm profile html '}
        ]

        m2._transform_to_complex_commands = Mock(return_value=param)
        with patch.object(bigip_command.V2Manager, 'commands', Mock(return_value=out)):
            res = m2.parse_commands()
            self.assertEqual(res, out)

        m1.want.is_tmsh = Mock(return_value=True)
        m1.execute_on_device = Mock(return_value=dict(command="modify cli preference pager disabled"))

        res5 = m1._execute(commands=['list ltm profile html'])

        self.assertDictEqual(res5, dict(command="modify cli preference pager disabled"))
