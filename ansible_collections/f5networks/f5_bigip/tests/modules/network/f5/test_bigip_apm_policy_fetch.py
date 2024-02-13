# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
from packaging.version import Version

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_apm_policy_fetch
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_fetch import (
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
            dest='/tmp/',
            force='yes',
            file='foo_export'
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.file, 'foo_export')

    def test_module_parameter_file(self):
        args = dict(
            dest='/tmp/',
            force='yes'
        )
        p = ModuleParameters(params=args)

        with patch.object(
            bigip_apm_policy_fetch.tempfile,
            '_get_candidate_names',
            Mock(return_value=iter(['tmpfile']))
        ):
            self.assertEqual(p.file, 'tmpfile.tar.gz')

    def test_module_parameter_fulldest(self):
        args = dict(
            dest='/tmp/'
        )
        p = ModuleParameters(params=args)

        with \
             patch.object(bigip_apm_policy_fetch.os.path, 'isdir', Mock(return_value=False)), \
             patch.object(bigip_apm_policy_fetch.os.path, 'exists', Mock(return_value=True)):
            self.assertEqual(p.fulldest, '/tmp/')

        with \
             patch.object(bigip_apm_policy_fetch.os.path, 'isdir', Mock(return_value=False)), \
             patch.object(bigip_apm_policy_fetch.os.path, 'exists', Mock(return_value=False)), \
             patch.object(bigip_apm_policy_fetch.os, 'stat', Mock()), \
             patch.object(bigip_apm_policy_fetch.os, 'access', Mock(side_effect=[True, False])):
            self.assertEqual(p.fulldest, '/tmp/')

            with self.assertRaises(F5ModuleError) as err:
                p.fulldest

            self.assertIn(f"Destination {os.path.dirname(p.dest)} not writable", err.exception.args[0])

        with \
             patch.object(bigip_apm_policy_fetch.os.path, 'isdir', Mock(return_value=False)), \
             patch.object(bigip_apm_policy_fetch.os.path, 'exists', Mock(return_value=False)), \
             patch.object(bigip_apm_policy_fetch.os, 'stat', Mock(side_effect=[OSError('permission denied'), OSError()])):
            with self.assertRaises(F5ModuleError) as err1:
                p.fulldest()

            with self.assertRaises(F5ModuleError) as err2:
                p.fulldest()

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
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_fetch.module_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_fetch.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_apm_policy_fetch.F5Client')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    @patch.object(bigip_apm_policy_fetch, 'tmos_version', Mock(return_value='15.0.0'))
    @patch.object(bigip_apm_policy_fetch, 'os', Mock(return_value=True))
    def test_create(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.post.side_effect = [
            {'code': 200, 'contents': {}},
            {'code': 200, 'contents': {'commandResult': {}}},
            {'code': 200, 'contents': {}},
        ]
        mm.client.get.return_value = {'code': 200, 'contents': {}}
        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 3)

    @patch.object(bigip_apm_policy_fetch,
                  'module_provisioned', Mock(return_value=False))
    def test_create_module_provision_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'APM must be provisioned to use this module.',
            err.exception.args[0])

    @patch.object(bigip_apm_policy_fetch,
                  'tmos_version', Mock(return_value='12.0.0'))
    @patch.object(bigip_apm_policy_fetch,
                  'Version', Mock(side_effect=[Version('12.0.0'), Version('14.0.0')]))
    def test_create_version_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'Due to bug ID685681 it is not possible to use this module on TMOS version below 14.x',
            err.exception.args[0])

    def test_create_on_device_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.version_less_than_14 = Mock(return_value=False)
        mm.exists = Mock(return_value=False)
        mm.client.post.side_effect = [
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {'commandResult': 'command not found'}},
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])
        self.assertIn(
            'Item export command failed with the error: command not found',
            err2.exception.args[0]
        )

    def test_create_move_file_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            type='access_policy',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.version_less_than_14 = Mock(return_value=False)
        mm.exists = Mock(return_value=False)
        mm.client.post.side_effect = [
            {'code': 200, 'contents': {}},
            {'code': 503, 'contents': 'service not available'},
            {'code': 200, 'contents': {}},
            {'code': 200, 'contents': {'commandResult': 'cannot stat'}}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('service not available', err1.exception.args[0])
        self.assertIn('cannot stat', err2.exception.args[0])

    @patch.object(bigip_apm_policy_fetch.os.path, 'exists', Mock(return_value=False))
    def test_create_file_download_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            type='access_policy',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.version_less_than_14 = Mock(return_value=False)
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Failed to download the remote file.",
            err.exception.args[0]
        )

    def test_create_remove_file_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            file='foo_export',
            type='access_policy',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.version_less_than_14 = Mock(return_value=False)
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock(return_value=True)
        mm.download = Mock()
        mm.client.post.return_value = {'code': 503, 'contents': 'service not available'}

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

    @patch.object(bigip_apm_policy_fetch, 'tmos_version', Mock(return_value='15.0.0'))
    def test_policy_does_not_exists_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            type='access_policy'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            {'code': 404},
            {'code': 503, 'contents': 'Service not available'}
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn(
            f'The provided {mm.want.type} with the name '
            f'{mm.want.name} does not exist on device.',
            err1.exception.args[0])

        self.assertIn('Service not available', err2.exception.args[0])

    @patch.object(bigip_apm_policy_fetch.os.path, 'exists', Mock(return_value=False))
    def test_export_create(self, *args):
        set_module_args(dict(
            name='fake_policy',
            type='access_policy',
            dest='/tmp/'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.version_less_than_14 = Mock(return_value=False)
        mm.policy_exists = Mock(return_value=False)
        mm.create = Mock(return_value=True)

        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_update_failure(self, *args):
        set_module_args(dict(
            name='fake_policy',
            type='access_policy',
            dest='/tmp/',
            force='no'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.version_less_than_14 = Mock(return_value=False)
        mm.exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            f"File '{mm.want.fulldest}' already exists.",
            err.exception.args[0]
        )

    @patch.object(bigip_apm_policy_fetch, 'Connection')
    @patch.object(bigip_apm_policy_fetch.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_apm_policy_fetch.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_apm_policy_fetch, 'Connection')
    @patch.object(bigip_apm_policy_fetch.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_apm_policy_fetch.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(bigip_apm_policy_fetch, 'HAS_PACKAGING', False)
    @patch.object(bigip_apm_policy_fetch, 'Connection')
    @patch.object(bigip_apm_policy_fetch.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_import_error(self, *args):
        set_module_args(dict(
            name='foobar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_apm_policy_fetch.PACKAGING_IMPORT_ERROR = "failed to import the 'packaging' package"
            bigip_apm_policy_fetch.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn(
            'Failed to import the required Python library (packaging)',
            result.exception.args[0]['msg']
        )
