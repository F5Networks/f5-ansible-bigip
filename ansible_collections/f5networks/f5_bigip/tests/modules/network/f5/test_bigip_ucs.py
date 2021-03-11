# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_ucs import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

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
            ucs="/root/bigip.localhost.localdomain.ucs",
            force=True,
            include_chassis_level_config=True,
            no_license=True,
            no_platform_check=True,
            passphrase="foobar",
            reset_trust=True,
            state='installed'
        )

        p = ModuleParameters(params=args)
        assert p.ucs == '/root/bigip.localhost.localdomain.ucs'
        assert p.force is True
        assert p.include_chassis_level_config is True
        assert p.no_license is True
        assert p.no_platform_check is True
        assert p.passphrase == "foobar"
        assert p.reset_trust is True
        assert p.install_command == \
            "tmsh load sys ucs /var/local/ucs/bigip.localhost.localdomain.ucs " \
            "include-chassis-level-config no-license no-platform-check " \
            "passphrase foobar reset-trust"

    def test_module_parameters_false_ucs_booleans(self):
        args = dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            include_chassis_level_config=False,
            no_license=False,
            no_platform_check=False,
            reset_trust=False
        )

        p = ModuleParameters(params=args)
        assert p.ucs == '/root/bigip.localhost.localdomain.ucs'
        assert p.include_chassis_level_config is False
        assert p.no_license is False
        assert p.no_platform_check is False
        assert p.reset_trust is False
        assert p.install_command == "tmsh load sys ucs /var/local/ucs/bigip.localhost.localdomain.ucs"


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()

    def tearDown(self):
        self.patcher1.stop()

    def test_ucs_default_present(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[False, True])

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_explicit_present(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[False, True])

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_installed(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='installed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)
        mm.install_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_absent_exists(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.remove_from_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[True, False])

        results = mm.exec_module()

        assert results['changed'] is True

    def test_ucs_absent_fails(self, *args):
        set_module_args(dict(
            ucs="/root/bigip.localhost.localdomain.ucs",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.remove_from_device = Mock(return_value=True)
        mm.exists = Mock(side_effect=[True, True])

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()
        assert 'Failed to delete' in str(res.exception)
