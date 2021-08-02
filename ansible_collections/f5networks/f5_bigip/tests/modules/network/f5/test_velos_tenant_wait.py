# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import paramiko

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.velos_tenant_wait import (
    Parameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, exit_json, fail_json, AnsibleFailJson
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
            name='tenant1',
            delay=3,
            state='ssh-ready',
            timeout=500,
            sleep=10,
            msg='We timed out during waiting for Tenant :-('
        )

        p = Parameters(params=args)
        assert p.name == 'tenant1'
        assert p.state == 'ssh-ready'
        assert p.delay == 3
        assert p.timeout == 500
        assert p.sleep == 10
        assert p.msg == 'We timed out during waiting for Tenant :-('


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)

    def test_wait_configured(self, *args):
        """ Transition from configured to provisioned state. """
        set_module_args(dict(
            name='defaultbip', state='configured'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        # Simulate the tenant is not present until the 3rd loop iteration at
        # which time it is present and in the configured state.
        mm.tenant_exists = Mock(side_effect=[False, False, True])
        configured_state = load_fixture('load_tenant_state_configured.json')
        mm.read_tenant_from_device = Mock(return_value=configured_state)

        results = mm.exec_module()
        assert results['changed'] is False
        assert results['elapsed'] >= 2
        assert mm.tenant_exists.called
        assert mm.read_tenant_from_device.called

    def test_wait_provisioned(self, *args):
        """ Transition from configured to provisioned state. """
        set_module_args(dict(
            name='defaultbip',
            state='provisioned'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        configured_state = load_fixture('load_tenant_state_configured.json')
        provisioned_state = load_fixture('load_tenant_state_provisioned.json')
        mm.read_tenant_from_device = Mock(side_effect=[configured_state, provisioned_state])

        results = mm.exec_module()
        assert results['changed'] is False
        assert mm.tenant_exists.call_count == 2
        assert mm.read_tenant_from_device.call_count == 2

    def test_wait_deployed(self, *args):
        """ Transition from provisioned to deployed state. """
        set_module_args(dict(
            name='defaultbip',
            state='deployed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        provisioned_state = load_fixture('load_tenant_state_provisioned.json')
        deployed_state = load_fixture('load_tenant_state_deployed.json')
        mm.read_tenant_from_device = Mock(side_effect=[provisioned_state, deployed_state])

        results = mm.exec_module()
        assert results['changed'] is False
        assert mm.tenant_exists.call_count == 2
        assert mm.read_tenant_from_device.call_count == 2

    def test_wait_ssh_ready(self, *args):
        """ Wait till tenant accepts ssh connections. """
        set_module_args(dict(
            name='defaultbip',
            state='ssh-ready'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        deployed_state = load_fixture('load_tenant_state_deployed.json')
        mm.read_tenant_from_device = Mock(return_value=deployed_state)

        # Simulate the first ssh connection attempt raises an SSHExecption
        # indicating ssh is not ready, followed by a second connection which
        # raises AuthenticationException, indicating ssh server is up.
        with patch.object(paramiko, 'SSHClient', autospec=True) as mock_ssh:
            mocked_client = MagicMock()
            attrs = {
                'connect.side_effect': [
                    paramiko.ssh_exception.SSHException,
                    paramiko.ssh_exception.AuthenticationException
                ]
            }
            mocked_client.configure_mock(**attrs)
            mock_ssh.return_value = mocked_client

            results = mm.exec_module()
            assert results['changed'] is False
            assert mm.tenant_exists.call_count == 2
            assert mocked_client.connect.call_count == 2

    def test_timeout_elapsed(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
            timeout=2
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(AnsibleFailJson):
            mm.exec_module()

    def test_invalid_timeout(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
            delay=1,
            sleep=3,
            timeout=2
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(F5ModuleError):
            # exception: The combined delay and sleep should not be greater than or equal to the timeout.
            mm.exec_module()

    def test_invalid_delay_timeout(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
            delay=2,
            sleep=2,
            timeout=1,

        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(F5ModuleError):
            # exception: The delay should not be greater than or equal to the timeout.
            mm.exec_module()
