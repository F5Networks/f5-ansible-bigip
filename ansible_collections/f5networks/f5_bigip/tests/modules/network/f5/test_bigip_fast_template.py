# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_template import (
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
            name='fake',
            source='/var/fake/fake.zip',
            state='present'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'fake'
        assert p.source == '/var/fake/fake.zip'

    def test_module_parameters_no_name(self):
        args = dict(
            source='/var/fake/fake.zip',
            state='present'
        )

        p = ModuleParameters(params=args)
        assert p.name == 'fake'
        assert p.source == '/var/fake/fake.zip'


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_fast_template.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_create_fast_template_set(self, *args):
        set_module_args(dict(
            source='/var/fake/fake.zip',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock(return_value=True)
        mm.remove_temp_file_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['source'] == '/var/fake/fake.zip'
        assert results['name'] == 'fake'

    def test_remove_fast_template(self, *args):
        set_module_args(dict(
            name='fake',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[True, False])
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['name'] == 'fake'

    def test_purge_all_fast_template_sets(self, *args):
        set_module_args(dict(
            state='purge'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)
        mm.purge_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
