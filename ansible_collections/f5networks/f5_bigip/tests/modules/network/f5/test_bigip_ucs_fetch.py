# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs_fetch import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import set_module_args


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
            backup='yes',
            create_on_missing='yes',
            encryption_password='my-password',
            dest='/tmp/foo.ucs',
            force='yes',
            fail_on_missing='no',
            src='remote.ucs',
            timeout=600
        )
        p = ModuleParameters(params=args)
        assert p.backup == 'yes'
        assert p.timeout == (6.0, 100)


class TestV1Manager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs_fetch.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_start_create_task(self, *args):
        task_id = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            src='remote.ucs',
            dest='/tmp/cs_backup.ucs',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.create_async_task_on_device = Mock(return_value=task_id)
        mm._start_task_on_device = Mock(return_value=True)

        results = mm.exec_module()
        assert results['changed'] is True
        assert results['task_id'] == task_id
        assert results['message'] == 'UCS async task started with id: {0}'.format(task_id)

    def test_check_task_download_ucs(self, *args):
        set_module_args(dict(
            backup='yes',
            dest='/tmp/foo.ucs',
            src='remote.ucs',
            task_id='e7550a12-994b-483f-84ee-761eb9af6750',
            timeout=400
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            add_file_common_args=self.spec.add_file_common_args,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.async_wait = Mock(return_value=True)
        mm._get_backup_file = Mock(return_value='/tmp/foo.backup')
        mm.download_from_device = Mock(return_value=True)
        mm._set_checksum = Mock(return_value=12345)
        mm._set_md5sum = Mock(return_value=54321)

        p1 = patch('os.path.exists', return_value=True)
        p1.start()
        p2 = patch('os.path.isdir', return_value=False)
        p2.start()

        results = mm.exec_module()

        p1.stop()
        p2.stop()

        assert results['changed'] is True
