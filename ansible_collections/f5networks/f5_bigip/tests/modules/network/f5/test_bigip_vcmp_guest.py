# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("F5 Ansible modules require Python >= 2.7")

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_vcmp_guest import (
    ModuleParameters, ApiParameters, Difference, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_vcmp_guest
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
            initial_image='BIGIP-12.1.0.1.0.1447-HF1.iso',
            mgmt_network='bridged',
            mgmt_address='1.2.3.4/24',
            vlans=[
                'vlan1',
                'vlan2'
            ]
        )

        p = ModuleParameters(params=args)
        assert p.initial_image == 'BIGIP-12.1.0.1.0.1447-HF1.iso'
        assert p.mgmt_network == 'bridged'

    def test_module_parameters_mgmt_bridged_without_subnet(self):
        args = dict(
            mgmt_network='bridged',
            mgmt_address='1.2.3.4'
        )

        p = ModuleParameters(params=args)
        assert p.mgmt_network == 'bridged'
        assert p.mgmt_address == '1.2.3.4/32'

    def test_module_parameters_mgmt_address_cidr(self):
        args = dict(
            mgmt_network='bridged',
            mgmt_address='1.2.3.4/24'
        )

        p = ModuleParameters(params=args)
        assert p.mgmt_network == 'bridged'
        assert p.mgmt_address == '1.2.3.4/24'

    def test_module_parameters_mgmt_address_subnet(self):
        args = dict(
            mgmt_network='bridged',
            mgmt_address='1.2.3.4/255.255.255.0'
        )

        p = ModuleParameters(params=args)
        assert p.mgmt_network == 'bridged'
        assert p.mgmt_address == '1.2.3.4/24'

    def test_module_parameters_mgmt_route(self):
        args = dict(
            mgmt_route='1.2.3.4'
        )

        p = ModuleParameters(params=args)
        assert p.mgmt_route == '1.2.3.4'

    def test_module_parameters_vcmp_software_image_facts(self):
        # vCMP images may include a forward slash in their names. This is probably
        # related to the slots on the system, but it is not a valid value to specify
        # that slot when providing an initial image
        args = dict(
            initial_image='BIGIP-12.1.0.1.0.1447-HF1.iso/1',
        )

        p = ModuleParameters(params=args)
        assert p.initial_image == 'BIGIP-12.1.0.1.0.1447-HF1.iso/1'

    def test_api_parameters(self):
        args = dict(
            initialImage="BIGIP-tmos-tier2-13.1.0.0.0.931.iso",
            managementGw="2.2.2.2",
            managementIp="1.1.1.1/24",
            managementNetwork="bridged",
            state="deployed",
            vlans=[
                "/Common/vlan1",
                "/Common/vlan2"
            ]
        )

        p = ApiParameters(params=args)
        assert p.initial_image == 'BIGIP-tmos-tier2-13.1.0.0.0.931.iso'
        assert p.mgmt_route == '2.2.2.2'
        assert p.mgmt_address == '1.1.1.1/24'
        assert '/Common/vlan1' in p.vlans
        assert '/Common/vlan2' in p.vlans

    def test_api_parameters_with_hotfix(self):
        args = dict(
            initialImage="BIGIP-14.1.0.3-0.0.6.iso",
            initialHotfix="Hotfix-BIGIP-14.1.0.3.0.5.6-ENG.iso",
            managementGw="2.2.2.2",
            managementIp="1.1.1.1/24",
            managementNetwork="bridged",
            state="deployed",
            vlans=[
                "/Common/vlan1",
                "/Common/vlan2"
            ]
        )

        p = ApiParameters(params=args)
        assert p.initial_image == 'BIGIP-14.1.0.3-0.0.6.iso'
        assert p.initial_hotfix == 'Hotfix-BIGIP-14.1.0.3.0.5.6-ENG.iso'
        assert p.mgmt_route == '2.2.2.2'
        assert p.mgmt_address == '1.1.1.1/24'
        assert '/Common/vlan1' in p.vlans
        assert '/Common/vlan2' in p.vlans

    def test_invalid_management_route_and_address_raise(self):
        route = ModuleParameters(client=Mock(), params=dict(mgmt_route='not-an-ip'))
        with self.assertRaisesRegex(F5ModuleError, 'mgmt_route'):
            route.mgmt_route

        address = ModuleParameters(client=Mock(), params=dict(mgmt_address='not-an-ip'))
        with self.assertRaisesRegex(F5ModuleError, 'mgmt_address'):
            address.mgmt_address

    def test_malformed_management_address_tuple_raises(self):
        p = ModuleParameters(client=Mock(), params=dict(mgmt_address='1.2.3.4/24/extra'))

        with self.assertRaisesRegex(F5ModuleError, 'mgmt_address is malformed'):
            p.mgmt_tuple

    def test_missing_initial_image_and_hotfix_raise(self):
        image = ModuleParameters(client=Mock(), params=dict(initial_image='missing.iso'))
        image.initial_image_exists = Mock(return_value=False)
        with self.assertRaisesRegex(F5ModuleError, 'initial_image'):
            image.initial_image

        hotfix = ModuleParameters(client=Mock(), params=dict(initial_hotfix='missing.iso'))
        hotfix.initial_hotfix_exists = Mock(return_value=False)
        with self.assertRaisesRegex(F5ModuleError, 'initial_hotfix'):
            hotfix.initial_hotfix

    def test_initial_image_and_hotfix_lookup_errors_raise(self):
        p = ModuleParameters(client=Mock(), params={})
        p.client.get = Mock(return_value=dict(code=500, contents='lookup failed'))

        with self.assertRaisesRegex(F5ModuleError, 'lookup failed'):
            p.initial_image_exists('image.iso')
        with self.assertRaisesRegex(F5ModuleError, 'lookup failed'):
            p.initial_hotfix_exists('hotfix.iso')

    def test_state_and_argument_choices(self):
        assert ModuleParameters(params=dict(state='present')).state == 'deployed'
        assert ModuleParameters(params=dict(state='disabled')).state == 'configured'
        spec = ArgumentSpec()
        assert spec.argument_spec['mgmt_network']['choices'] == ['bridged', 'isolated', 'host only']
        assert spec.argument_spec['state']['choices'] == ['configured', 'disabled', 'provisioned', 'absent', 'present']


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.patcher1 = patch('time.sleep')
        self.patcher1.start()

        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_vcmp_guest.ModuleParameters.initial_image_exists')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_vcmp_guest.ModuleParameters.initial_hotfix_exists')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_vcmp_guest.send_teem')
        self.m3 = self.p3.start()
        self.m3.return_value = True

    def tearDown(self):
        self.patcher1.stop()
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_create_vcmpguest(self, *args):
        set_module_args(dict(
            name="guest1",
            mgmt_network="bridged",
            mgmt_address="10.10.10.10/24",
            initial_image="BIGIP-13.1.0.0.0.931.iso"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=False)
        mm.is_deployed = Mock(side_effect=[False, True, True, True, True])
        mm.deploy_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['name'] == 'guest1'

    def test_create_vcmpguest_with_hotfix(self, *args):
        set_module_args(dict(
            name="guest2",
            mgmt_network="bridged",
            mgmt_address="10.10.10.10/24",
            initial_image="BIGIP-14.1.0.3-0.0.6.iso",
            initial_hotfix="Hotfix-BIGIP-14.1.0.3.0.5.6-ENG.iso"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.create_on_device = Mock(return_value=True)
        mm.exists = Mock(return_value=False)
        mm.is_deployed = Mock(side_effect=[False, True, True, True, True])
        mm.deploy_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['name'] == 'guest2'

    def test_update_idempotent(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.read_current_from_device = Mock()
        manager.should_update = Mock(return_value=False)
        manager.module = Mock(check_mode=False)

        assert manager.update() is False
        manager.read_current_from_device.assert_called_once()

    def test_update_changes_and_lifecycle_states(self):
        for state, action in (('configured', 'configure'), ('provisioned', 'provision'), ('deployed', 'deploy')):
            manager = ModuleManager.__new__(ModuleManager)
            manager.read_current_from_device = Mock()
            manager.should_update = Mock(return_value=True)
            manager.module = Mock(check_mode=False)
            manager.changes = Mock(cores_per_slot=None)
            manager.want = Mock(state=state)
            manager.update_on_device = Mock()
            manager.configure = Mock()
            manager.provision = Mock()
            manager.deploy = Mock()

            assert manager.update() is True
            manager.update_on_device.assert_called_once()
            getattr(manager, action).assert_called_once()

    def test_absent_state_and_failed_delete(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.exists = Mock(return_value=False)
        assert manager.absent() is False

        manager.module = Mock(check_mode=False)
        manager.want = Mock(delete_virtual_disk=False)
        manager.remove_from_device = Mock()
        manager.exists = Mock(return_value=True)
        with self.assertRaisesRegex(F5ModuleError, 'Failed to delete'):
            manager.remove()

    def test_update_management_address_requires_subnet(self):
        want = Mock(mgmt_tuple=Mock(subnet=None))
        diff = Difference(want, Mock())

        with self.assertRaisesRegex(F5ModuleError, 'subnet must be specified'):
            diff.mgmt_address

    def test_manager_transport_errors_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='guest1')
        manager.client = Mock(get=Mock(return_value=dict(code=500, contents='request failed')))

        with self.assertRaisesRegex(F5ModuleError, 'request failed'):
            manager.exists()
        with self.assertRaisesRegex(F5ModuleError, 'request failed'):
            manager.read_current_from_device()
        with self.assertRaisesRegex(F5ModuleError, 'request failed'):
            manager.get_virtual_disks_on_device()
        with self.assertRaisesRegex(F5ModuleError, 'request failed'):
            manager.is_configured()
        with self.assertRaisesRegex(F5ModuleError, 'request failed'):
            manager.is_provisioned()
        with self.assertRaisesRegex(F5ModuleError, 'request failed'):
            manager.is_deployed()

    def test_manager_mutation_errors_raise(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='guest1')
        manager.changes = Mock(api_params=Mock(return_value={}))
        manager.client = Mock(
            post=Mock(return_value=dict(code=500, contents='mutation failed')),
            patch=Mock(return_value=dict(code=500, contents='mutation failed')),
            delete=Mock(return_value=dict(code=500, contents='mutation failed')),
            get=Mock(return_value=dict(code=200, contents={'items': [dict(name='guest1.img')]}))
        )
        manager.have = Mock(virtual_disk='guest1.img')

        for operation in (manager.create_on_device, manager.update_on_device, manager.remove_from_device,
                          manager.configure_on_device, manager.provision_on_device, manager.deploy_on_device,
                          manager.remove_virtual_disk_from_device):
            with self.assertRaisesRegex(F5ModuleError, 'mutation failed'):
                operation()

    def test_delete_virtual_disk_and_state_checks(self):
        manager = ModuleManager.__new__(ModuleManager)
        manager.want = Mock(name='guest1')
        manager.have = Mock(virtual_disk='guest1.img')
        manager.get_virtual_disks_on_device = Mock(return_value={'items': [dict(name='guest1.img/1')]})
        manager.client = Mock(delete=Mock(return_value=dict(code=200, contents={})))

        assert manager.remove_virtual_disk() is True
        manager.client.delete.assert_called_once_with('/mgmt/tm/vcmp/virtual-disk/guest1.img~1')

        manager.client.get = Mock(return_value=dict(code=404, contents={}))
        assert manager.is_configured() is True
        assert manager.is_provisioned() is False
        assert manager.is_deployed() is False

    def test_main_function_success(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.return_value = {'changed': False}
        with patch.object(bigip_vcmp_guest, 'AnsibleModule', return_value=module), \
                patch.object(bigip_vcmp_guest, 'Connection'), \
                patch.object(bigip_vcmp_guest, 'ModuleManager', return_value=manager):
            bigip_vcmp_guest.main()

        module.exit_json.assert_called_once_with(changed=False)

    def test_main_function_failed(self):
        module = Mock(_socket_path='/tmp/socket')
        manager = Mock()
        manager.exec_module.side_effect = F5ModuleError('guest failed')
        with patch.object(bigip_vcmp_guest, 'AnsibleModule', return_value=module), \
                patch.object(bigip_vcmp_guest, 'Connection'), \
                patch.object(bigip_vcmp_guest, 'ModuleManager', return_value=manager):
            bigip_vcmp_guest.main()

        module.fail_json.assert_called_once_with(msg='guest failed')
