# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_regkey_license_assignment import (
    ArgumentSpec, ModuleManager, ModuleParameters
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
    def test_module_parameters_unmanaged(self):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=False,
            device_username='admin',
            device_password='secret',
            device_port='8443'
        )

        p = ModuleParameters(params=args)
        assert p.pool == 'foo-pool'
        assert p.key == 'XXXX-XXXX-XXXX-XXXX-XXXX'
        assert p.device == '1.1.1.1'
        assert p.managed is False
        assert p.device_username == 'admin'
        assert p.device_password == 'secret'
        assert p.device_port == 8443

    def test_module_parameters_managed(self):
        args = dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            managed=True,
        )

        p = ModuleParameters(params=args)
        assert p.pool == 'foo-pool'
        assert p.key == 'XXXX-XXXX-XXXX-XXXX-XXXX'
        assert p.device == '1.1.1.1'
        assert p.managed is True


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()

    def tearDown(self):
        self.patcher1.stop()

    def test_create(self, *args):
        set_module_args(dict(
            pool='foo-pool',
            key='XXXX-XXXX-XXXX-XXXX-XXXX',
            device='1.1.1.1',
            device_username='admin',
            device_password='secret',
            managed='no',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(side_effect=[False, True])
        mm.create_on_device = Mock(return_value=True)
        mm.wait_for_device_to_be_licensed = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
