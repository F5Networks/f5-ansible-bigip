# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_do_deploy import (
    Parameters, ArgumentSpec, ModuleManager
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
            content=dict(param1='foo', param2='bar'),
            timeout=600
        )
        p = Parameters(params=args)
        assert p.content == dict(param1='foo', param2='bar')
        assert p.timeout == 600


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_do_deploy.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.patcher1.stop()
        self.p2.stop()

    def test_start_declaration_task(self, *args):
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        declaration = load_fixture('do_declaration.json')
        set_module_args(dict(
            content=declaration,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.upsert_on_device = Mock(return_value="e7550a12-994b-483f-84ee-761eb9af6750")
        results = mm.exec_module()

        assert results['changed'] is True
        assert results['task_id'] == uuid
        assert results['message'] == "DO async task started with id: {0}".format(uuid)

    def test_check_declaration_task_status(self, *args):
        response = (200, {"result": {"status": "FINISHED", "message": "success"}})
        uuid = "e7550a12-994b-483f-84ee-761eb9af6750"
        set_module_args(dict(
            task_id=uuid,
            timeout=500
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        # Override methods to force specific logic in the module to happen
        mm._check_task_on_device = Mock(return_value=response)

        results = mm.exec_module()

        assert results['changed'] is True
        assert mm.want.timeout == (5.0, 100)
