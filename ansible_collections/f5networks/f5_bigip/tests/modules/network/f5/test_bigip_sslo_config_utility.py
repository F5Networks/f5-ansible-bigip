# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility import (
    Parameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
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
            package='MyApp-0.1.0-0001.noarch.rpm',
            utility='rpm-update'
        )
        p = Parameters(params=args)
        assert p.package == 'MyApp-0.1.0-0001.noarch.rpm'
        assert p.utility == 'rpm-update'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('time.sleep')
        self.p1.start()
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_sslo_config_utility.sslo_version')
        self.m3 = self.p3.start()
        self.m3.return_value = "9.0"

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_update_rpm_package_success(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        expected = {'operation': 'INSTALL', 'packageFilePath': '/var/config/rest/downloads/MyApp-0.1.0-0001.noarch.rpm'}

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.upload_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('sslo_rpm_update_succeed.json')))

        results = mm.exec_module()

        assert results['changed'] is True
        assert mm.client.post.call_count == 1
        assert mm.client.get.call_count == 1
        assert mm.client.post.call_args[1]['data'] == expected

    def test_update_rpm_package_failure_generic_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.upload_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200,
                                               contents=load_fixture('sslo_rpm_update_failed_error_not_provided.json')))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert "SSL Orchestrator package update failed, check BIG-IP logs for root cause." in str(res.exception)

    def test_update_rpm_package_failure_specific_error(self, *args):
        package_name = os.path.join(fixture_path, 'MyApp-0.1.0-0001.noarch.rpm')
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            package=package_name,
            utility='rpm-update',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.upload_to_device = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=202, contents=load_fixture('sslo_rpm_update_start.json')))
        mm.client.get = Mock(return_value=dict(code=200,
                                               contents=load_fixture('sslo_rpm_update_failed_error_provided.json')))

        with self.assertRaises(F5ModuleError) as res:
            mm.exec_module()

        assert "Package MyApp-0.1.0-0001.noarch.rpm is corrupted, aborting." in str(res.exception)

    def test_remove_sslo_config(self):
        set_module_args(dict(
            timeout=60,
            utility='delete-all',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.same_sslo_version = Mock(return_value=False)
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
