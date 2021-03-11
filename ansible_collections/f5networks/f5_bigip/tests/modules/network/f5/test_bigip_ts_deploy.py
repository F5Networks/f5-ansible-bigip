# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ts_deploy import (
    Parameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock
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
        )
        p = Parameters(params=args)
        assert p.content == dict(param1='foo', param2='bar')


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()

    def test_upsert_ts_declaration(self, *args):
        declaration = load_fixture('ts_declaration.json')
        set_module_args(dict(
            content=declaration,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.upsert_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_upsert_ts_declaration_no_change(self, *args):
        declaration = load_fixture('ts_declaration.json')
        set_module_args(dict(
            content=declaration,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.read_from_device = Mock(return_value=load_fixture('ts_response.json'))

        results = mm.exec_module()

        assert results['changed'] is False

    def test_remove_ts_declaration(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.read_from_device = Mock(return_value=load_fixture('ts_response.json'))
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_remove_ts_declaration_no_change(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.read_from_device = Mock(return_value=load_fixture('ts_deleted_response.json'))

        results = mm.exec_module()

        assert results['changed'] is False
