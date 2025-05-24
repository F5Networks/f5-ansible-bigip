# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_asm_policy_fetch
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_fetch import (
    ModuleParameters, ModuleManager, ArgumentSpec
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
            inline='yes',
            compact='no',
            base64='yes',
            dest='/tmp/foo.xml',
            force='yes',
            file='foo.xml',
            format="json"
        )
        p = ModuleParameters(params=args)

        self.assertTrue(p.inline)
        self.assertTrue(p.base64)
        self.assertFalse(p.compact)
        self.assertEqual(p.file, 'foo.xml')
        self.assertEqual(p.format, 'json')

    def test_module_params_alternate_values(self):
        args = dict(
            inline='no',
            compact='yes',
            base64='no',
            format="xml"
        )

        p = ModuleParameters(params=args)

        self.assertTrue(p.compact)
        self.assertFalse(p.inline)
        self.assertFalse(p.base64)
        self.assertEqual(p.format, 'xml')

    @patch.object(bigip_asm_policy_fetch.tempfile,
                  '_get_candidate_names',
                  Mock(return_value=iter(['tempfile', 'tempfile'])))
    def test_module_file_parameter(self):
        args1 = dict(format="binary")
        args2 = dict(format="xml")

        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        self.assertEqual(p1.file, 'tempfile.plc')
        self.assertEqual(p2.file, 'tempfile.xml')

    def test_module_parameter_fulldest(self):
        args = dict(
            dest='/tmp/',
            file='foo.xml'
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.fulldest, os.path.join(p.dest, p.file))

        with \
                patch.object(bigip_asm_policy_fetch.os.path, 'isdir', Mock(return_value=False)), \
                patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=True)):
            self.assertEqual(p.fulldest, '/tmp/')

        with \
                patch.object(bigip_asm_policy_fetch.os.path, 'isdir', Mock(return_value=False)), \
                patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=False)), \
                patch.object(bigip_asm_policy_fetch.os, 'stat', Mock()), \
                patch.object(bigip_asm_policy_fetch.os, 'access', Mock(side_effect=[True, False])):
            self.assertEqual(p.fulldest, '/tmp/')

            with self.assertRaises(F5ModuleError) as err:
                p.fulldest

            self.assertIn(f"Destination {os.path.dirname(p.dest)} not writable", err.exception.args[0])

        with \
                patch.object(bigip_asm_policy_fetch.os.path, 'isdir', Mock(return_value=False)), \
                patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=False)), \
                patch.object(bigip_asm_policy_fetch.os, 'stat', Mock(side_effect=[OSError('permission denied'), OSError()])):

            with self.assertRaises(F5ModuleError) as err1:
                p.fulldest

            with self.assertRaises(F5ModuleError) as err2:
                p.fulldest

            self.assertIn(
                f"Destination directory {os.path.dirname(p.dest)} is not accessible",
                err1.exception.args[0]
            )

            self.assertIn(
                f"Destination directory {os.path.dirname(p.dest)} does not exist",
                err2.exception.args[0]
            )


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_fetch.module_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_fetch.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_asm_policy_fetch.F5Client')
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

    @patch.object(bigip_asm_policy_fetch, 'module_provisioned',
                  Mock(return_value=False))
    def test_module_provision_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format='json'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "ASM must be provisioned to use this module.",
            err.exception.args[0]
        )

    def test_update_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            dest='/tmp/',
            force='no',
            format="xml"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f"File '{mm.want.fulldest}' already exists.",
            err.exception.args[0]
        )

    @patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=False))
    def test_download_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            dest='/tmp/',
            format='json'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.create_on_device = Mock()

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'Failed to download the remote file.',
            err.exception.args[0]
        )

    def test_remove_temp_file_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            dest='/tmp/',
            format='xml'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.create_on_device = Mock()
        mm.download = Mock()
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_policy_exists_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format='json'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn(
            f"The specified ASM policy {mm.want.name} "
            f"on partition {mm.want.partition} does not exist on device.",
            err2.exception.args[0]
        )

    @patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=True))
    def test_create(self, *args):
        name = 'fake_policy'
        partition = 'Common'
        set_module_args(dict(
            name=name,
            file='foobar.xml',
            dest='/tmp/foobar.xml',
            format='xml'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'items': [{'name': name, 'partition': partition}]}},
            {'code': 200, 'contents': {'items': [{'name': name, 'partition': partition, 'selfLink': '/policy/link'}]}},
            {'code': 200, 'contents': {'status': 'COMPLETED', 'result': {'fileSize': 100}}}
        ]
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 1}}

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=False))
    def test_create_on_device_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            dest='/tmp/',
            format='json'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.policy_exists = Mock(return_value=False)
        mm.client.post.return_value = {
            'code': 503,
            'contents': 'service not available'
        }
        mm.client.get.return_value = {
            'code': 200,
            'contents': {
                'items': [
                    {
                        'name': 'fake_policy',
                        'selfLink': 'https://selflink1'
                    },
                    {
                        'name': 'fake_policy2',
                        'selfLink': 'https://selflink2'
                    }
                ]
            }
        }

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    def test_create_on_device_inline_file_name(self, *args):
        set_module_args(dict(
            name='fake_policy',
            inline='yes',
            format='xml'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        policy_file = 'inline_policy_file'
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm._set_policy_link = Mock()
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 1}}
        mm.client.get.return_value = {
            'code': 200,
            'contents': {
                'status': 'COMPLETED',
                'result': {
                    'file': policy_file,
                    'fileSize': 100
                }
            },
        }

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['inline_policy'], policy_file)

    def test_create_set_policy_link_error(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format='xml'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.get.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])
        self.assertIn('The policy was not found', err2.exception.args[0])

    @patch.object(bigip_asm_policy_fetch.os.path, 'exists', Mock(return_value=True))
    def test_create_binary(self, *args):
        name = 'fake_policy'
        partition = 'Common'
        set_module_args(dict(
            name=name,
            file='foobar.xml',
            dest='/tmp/foobar.xml',
            format='binary'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = {'code': 200, 'contents': {'items': [{'name': name, 'partition': partition}]}}
        mm.client.post.side_effect = [
            {'code': 200, 'contents': {'id': 1, 'commandResult': {}}},
            {'code': 200, 'contents': {'commandResult': 'size of file /var/tmp/foobar.xml 100'}},
            {'code': 200, 'contents': {'commandResult': {}}},
            {'code': 200}
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_export_binary_on_device_failures(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format='binary'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': 'error: command not found'}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])
        self.assertIn('error: command not found', err2.exception.args[0])

    def test_stat_binary_on_device_failures(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format="binary"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        export_binary_post = {'code': 200, 'contents': {}}
        mm.client.post.side_effect = [
            export_binary_post,
            {'code': 503, 'contents': 'service not available'},
            export_binary_post,
            {'code': 200, 'contents': {}},
            export_binary_post,
            {'code': 200, 'contents': {'commandResult': 'error: command not found'}},
            export_binary_post,
            {'code': 200, 'contents': {'commandResult': 'file not found'}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err3:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err4:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])
        self.assertIn(
            'Failed to obtain file information, aborting.',
            err2.exception.args[0]
        )
        self.assertIn('error: command not found', err3.exception.args[0])
        self.assertIn(
            'Cannot get size of exported binary file, aborting',
            err4.exception.args[0]
        )

    def test_move_binary_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format="binary"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm._stat_binary_on_device = Mock()
        export_binary_post = {'code': 200, 'contents': {}}
        mm.client.post.side_effect = [
            export_binary_post,
            {'code': 503, 'contents': 'service not available'},
            export_binary_post,
            {'code': 200, 'contents': {'commandResult': 'cannot stat'}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])
        self.assertIn('cannot stat', err2.exception.args[0])

    def test_wait_for_task(self, *args):
        set_module_args(dict(
            name='fake_policy',
            format="xml"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm._set_policy_link = Mock()
        mm.client.post.return_value = {'code': 200, 'contents': {'id': 1}}
        mm.client.get.side_effect = [
            {'code': 200, 'contents': {'status': 'IN PROGRESS'}},
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'status': 'FAILURE'}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('Failed to export ASM policy.', err2.exception.args[0])

    @patch.object(bigip_asm_policy_fetch, 'Connection')
    @patch.object(bigip_asm_policy_fetch.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foobar.xml',
            dest='/tmp/foobar.xml',
            format='json'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_asm_policy_fetch.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_asm_policy_fetch, 'Connection')
    @patch.object(bigip_asm_policy_fetch.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foobar.xml',
            dest='/tmp/foobar.xml',
            format='xml'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_asm_policy_fetch.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
