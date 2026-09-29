# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigiq_device_info
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info import (
    Parameters, ArgumentSpec, ModuleManager, ApplicationsFactManager, ManagedDevicesFactManager,
    PurchasedPoolLicensesFactManager, RegkeyPoolsFactManager, SystemInfoFactManager, VlansFactManager,
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, AnsibleFailJson, AnsibleExitJson, fail_json, exit_json
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
            gather_subset=['system-info'],
        )
        p = Parameters(params=args)
        assert p.gather_subset == ['system-info']


class TestApplicationFactManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_success(self, *args):
        set_module_args(dict(
            gather_subset=['applications'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = ApplicationsFactManager(module=module, client=Mock())

        expected = {'protection_mode': 'Not Protected', 'id': '155d59ce-2e7f-3402-a2f0-e42990779f7e',
                    'name': 'another_one', 'status': 'DEPLOYED', 'health': 'Good', 'active_alerts': 0,
                    'bad_traffic': 0.0, 'enhanced_analytics': 'no', 'bad_traffic_growth': 'no'}
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents=load_fixture('load_bigiq_app.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['applications'][0], expected)

    def test_get_facts_failed(self, *args):
        set_module_args(dict(
            gather_subset=['applications'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = ApplicationsFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=404, contents='not found')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])


class TestManagedDevicesFactManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_success(self, *args):
        set_module_args(dict(
            gather_subset=['managed-devices'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = ManagedDevicesFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents=load_fixture('load_bigiq_devices.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['managed_devices']), 4)
        self.assertEqual(results['managed_devices'][0]['address'], '10.144.74.183')
        self.assertEqual(results['managed_devices'][3]['address'], '10.145.73.178')

    def test_get_facts_failed(self, *args):
        set_module_args(dict(
            gather_subset=['managed-devices'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = ManagedDevicesFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=404, contents='not found')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])


class TestPurchasedPoolLicensesFactManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_success(self, *args):
        set_module_args(dict(
            gather_subset=['purchased-pool-licenses'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {'dossier': '5d54d976', 'name': 'License for XXXX-XXXX-XXXX-XXXX-XXXX',
                    'vendor': 'F5 Networks, Inc.', 'licensed_date_time': '2017-12-12T00:00:00-08:00',
                    'licensed_version': '5.3.0', 'evaluation_start_date_time': '2017-12-11T00:00:00-08:00',
                    'evaluation_end_date_time': '2018-01-12T00:00:00-08:00',
                    'license_end_date_time': '2018-01-12T00:00:00-08:00',
                    'license_start_date_time': '2017-12-11T00:00:00-08:00',
                    'registration_key': 'XXXX-XXXX-XXXX-XXXX-XXXX'
                    }
        tm = PurchasedPoolLicensesFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents=load_fixture('load_bigiq_purchase_pools.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['purchased_pool_licenses'][0], expected)

    def test_get_facts_failed(self, *args):
        set_module_args(dict(
            gather_subset=['purchased-pool-licenses'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = PurchasedPoolLicensesFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=404, contents='not found')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])


class TestRegkeyPoolsLicensesFactManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_success(self, *args):
        set_module_args(dict(
            gather_subset=['regkey-pools'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = RegkeyPoolsFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_bigiq_licenses.json')),
            dict(code=200, contents=load_fixture('load_bigiq_license_offer.json')),
            dict(code=200, contents=load_fixture('load_bigiq_license_offer_2.json')),
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['regkey_pools'][0]['name'], 'GLOBAL-ENV')
        self.assertEqual(results['regkey_pools'][0]['total_offerings'], 0)
        self.assertEqual(results['regkey_pools'][1]['name'], 'myLicencePool')
        self.assertEqual(results['regkey_pools'][1]['total_offerings'], 1)

    def test_get_facts_failed(self, *args):
        set_module_args(dict(
            gather_subset=['regkey-pools'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = RegkeyPoolsFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=404, contents='not found'),
            dict(code=200, contents=load_fixture('load_bigiq_licenses.json')),
            dict(code=403, contents='Forbidden')
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('not found', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('Forbidden', err2.exception.args[0])


class TestSystemInfoFactManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_success(self, *args):
        set_module_args(dict(
            gather_subset=['system-info'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {'day': 31, 'hour': 9, 'minute': 20, 'month': 5, 'second': 20, 'year': 2023}
        tm = SystemInfoFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_bigiq_hw_info.json')),
            dict(code=200, contents=load_fixture('load_bigiq_system_setup.json')),
            dict(code=200, contents=load_fixture('load_bigiq_clock_info.json')),
            dict(code=200, contents=load_fixture('load_bigiq_version.json')),
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['system_info']['time'], expected)
        self.assertEqual(results['system_info']['package_version'], 'Build 0.0.1458 - Mon Apr  6 20:17:46 PDT 2020')
        self.assertEqual(results['system_info']['product_build_date'], 'Mon Apr  6 20:17:46 PDT 2020')
        self.assertEqual(len(results['system_info']['hardware_information']), 2)

    def test_get_facts_failed(self, *args):
        set_module_args(dict(
            gather_subset=['system-info'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = SystemInfoFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=404, contents='not found'),
            dict(code=200, contents=load_fixture('load_bigiq_hw_info.json')),
            dict(code=403, contents='Forbidden'),
            dict(code=200, contents=load_fixture('load_bigiq_hw_info.json')),
            dict(code=200, contents=load_fixture('load_bigiq_system_setup.json')),
            dict(code=401, contents='Unauthorized'),
            dict(code=200, contents=load_fixture('load_bigiq_hw_info.json')),
            dict(code=200, contents=load_fixture('load_bigiq_system_setup.json')),
            dict(code=200, contents=load_fixture('load_bigiq_clock_info.json')),
            dict(code=500, contents='Internal Server Error')
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('not found', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('Forbidden', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.exec_module()

        self.assertIn('Unauthorized', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.exec_module()

        self.assertIn('Internal Server Error', err4.exception.args[0])


class TestVlansFactManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_success(self, *args):
        set_module_args(dict(
            gather_subset=['vlans'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {'full_path': '/Common/internal', 'name': 'internal', 'auto_lasthop': 'default',
                    'cmp_hash_algorithm': 'default', 'failsafe_action': 'failover-restart-tm',
                    'failsafe_enabled': 'no', 'failsafe_timeout': 90, 'if_index': 112,
                    'learning_mode': 'enable-forward',
                    'interfaces': [{'name': '1.0', 'full_path': '1.0', 'tagged': 'no'}],
                    'mtu': 1500, 'sflow_poll_interval': 0, 'sflow_poll_interval_global': 'yes',
                    'sflow_sampling_rate': 0, 'sflow_sampling_rate_global': 'yes',
                    'source_check_enabled': 'disabled', 'true_mac_address': 'fa:16:3e:e0:f4:75', 'tag': 4094
                    }
        tm = VlansFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_bigiq_vlan.json')),
            dict(code=200, contents=load_fixture('load_bigiq_vlan_stats.json'))
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['vlans']), 1)
        self.assertDictEqual(results['vlans'][0], expected)

    def test_get_facts_failed(self, *args):
        set_module_args(dict(
            gather_subset=['vlans'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        tm = VlansFactManager(module=module, client=Mock())

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=404, contents='not found'),
            dict(code=200, contents=load_fixture('load_bigiq_vlan.json')),
            dict(code=403, contents='Forbidden')
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.exec_module()

        self.assertIn('not found', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exec_module()

        self.assertIn('Forbidden', err2.exception.args[0])


class TestModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_main_module_manager(self, *args):
        set_module_args(dict(
            gather_subset=[
                'all',
                '!system-info',
                '!vlans'
            ],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(side_effect=[{'foobar:': 'barfoo'}, {}])

        result = mm.exec_module()
        self.assertTrue(result['changed'])

        result = mm.exec_module()
        self.assertFalse(result['changed'])

        set_module_args(dict(
            gather_subset=[
                '!all'
            ],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        result = mm.exec_module()
        self.assertFalse(result['changed'])

        self.assertFalse(mm.get_manager('foo'))


class TestMainFunction(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.mock_module_helper.stop()

    @patch.object(bigiq_device_info, 'Connection')
    @patch.object(bigiq_device_info.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            gather_subset=['all']
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigiq_device_info.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigiq_device_info, 'Connection')
    @patch.object(bigiq_device_info.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            gather_subset=['all']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigiq_device_info.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])


class TestApplicationsFactManagerEdgeCases(unittest.TestCase):
    """Test edge cases and error scenarios for ApplicationsFactManager"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_empty_collection(self, *args):
        """Test handling of empty applications collection"""
        set_module_args(dict(gather_subset=['applications']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ApplicationsFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents={'result': {'items': []}})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['applications']), 0)

    def test_get_facts_403_forbidden(self, *args):
        """Test 403 Forbidden error"""
        set_module_args(dict(gather_subset=['applications']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ApplicationsFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=403, contents='Forbidden')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Forbidden', err.exception.args[0])

    def test_get_facts_500_server_error(self, *args):
        """Test 500 Internal Server Error"""
        set_module_args(dict(gather_subset=['applications']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ApplicationsFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=500, contents='Internal Server Error')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Internal Server Error', err.exception.args[0])


class TestManagedDevicesFactManagerEdgeCases(unittest.TestCase):
    """Test edge cases and error scenarios for ManagedDevicesFactManager"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_empty_collection(self, *args):
        """Test handling of empty managed devices collection"""
        set_module_args(dict(gather_subset=['managed-devices']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ManagedDevicesFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents={'items': []})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['managed_devices']), 0)

    def test_get_facts_401_unauthorized(self, *args):
        """Test 401 Unauthorized error"""
        set_module_args(dict(gather_subset=['managed-devices']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ManagedDevicesFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=401, contents='Unauthorized')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Unauthorized', err.exception.args[0])

    def test_get_facts_with_is_clustered_property(self, *args):
        """Test boolean property transformation for is_clustered"""
        set_module_args(dict(gather_subset=['managed-devices']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ManagedDevicesFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents=load_fixture('load_bigiq_devices.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        for device in results['managed_devices']:
            self.assertIn(device['is_clustered'], ['yes', 'no', True, False])


class TestPurchasedPoolLicensesFactManagerEdgeCases(unittest.TestCase):
    """Test edge cases and error scenarios for PurchasedPoolLicensesFactManager"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_empty_collection(self, *args):
        """Test handling of empty purchased pool licenses"""
        set_module_args(dict(gather_subset=['purchased-pool-licenses']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = PurchasedPoolLicensesFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents={'items': []})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['purchased_pool_licenses']), 0)

    def test_get_facts_502_bad_gateway(self, *args):
        """Test 502 Bad Gateway error"""
        set_module_args(dict(gather_subset=['purchased-pool-licenses']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = PurchasedPoolLicensesFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=502, contents='Bad Gateway')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Bad Gateway', err.exception.args[0])


class TestRegkeyPoolsFactManagerEdgeCases(unittest.TestCase):
    """Test edge cases and error scenarios for RegkeyPoolsFactManager"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_empty_pools(self, *args):
        """Test handling of empty regkey pools"""
        set_module_args(dict(gather_subset=['regkey-pools']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = RegkeyPoolsFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents={'items': []})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['regkey_pools']), 0)

    def test_get_facts_multiple_api_calls_partial_failure(self, *args):
        """Test failure on second API call in multi-call scenario"""
        set_module_args(dict(gather_subset=['regkey-pools']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = RegkeyPoolsFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_bigiq_licenses.json')),
            dict(code=500, contents='Internal Server Error')
        ]

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Internal Server Error', err.exception.args[0])


class TestSystemInfoFactManagerEdgeCases(unittest.TestCase):
    """Test edge cases and error scenarios for SystemInfoFactManager"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_partial_data(self, *args):
        """Test handling when some system info API calls succeed"""
        set_module_args(dict(gather_subset=['system-info']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = SystemInfoFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_bigiq_hw_info.json')),
            dict(code=200, contents=load_fixture('load_bigiq_system_setup.json')),
            dict(code=200, contents=load_fixture('load_bigiq_clock_info.json')),
            dict(code=200, contents=load_fixture('load_bigiq_version.json')),
        ]

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('time', results['system_info'])
        self.assertIn('hardware_information', results['system_info'])


class TestVlansFactManagerEdgeCases(unittest.TestCase):
    """Test edge cases and error scenarios for VlansFactManager"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_get_facts_empty_vlans(self, *args):
        """Test handling of empty vlans collection"""
        set_module_args(dict(gather_subset=['vlans']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = VlansFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents={'items': []})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(len(results['vlans']), 0)

    def test_get_facts_stats_call_failure(self, *args):
        """Test failure when stats API call fails"""
        set_module_args(dict(gather_subset=['vlans']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = VlansFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('load_bigiq_vlan.json')),
            dict(code=503, contents='Service Unavailable')
        ]

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Service Unavailable', err.exception.args[0])


class TestModuleManagerGatherSubsetFiltering(unittest.TestCase):
    """Test gather_subset parameter filtering and combinations"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_gather_subset_single_fact(self):
        """Test single fact type gathering"""
        set_module_args(dict(gather_subset=['applications']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value={'applications': []})

        result = mm.exec_module()

        self.assertTrue(result['changed'])

    def test_gather_subset_all_with_exclusion(self):
        """Test 'all' keyword with specific exclusion"""
        set_module_args(dict(gather_subset=['all', '!vlans']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Verify that after processing, vlans is not in the gather_subset
        mm.handle_all_keyword()
        mm.filter_excluded_meta_facts()
        result = mm.filter_excluded_facts()

        self.assertNotIn('vlans', result)
        self.assertIn('applications', result)
        self.assertIn('managed-devices', result)

    def test_gather_subset_multiple_exclusions(self):
        """Test multiple exclusions"""
        set_module_args(dict(
            gather_subset=['all', '!vlans', '!system-info', '!applications']
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        mm.handle_all_keyword()
        mm.filter_excluded_meta_facts()
        result = mm.filter_excluded_facts()

        self.assertNotIn('vlans', result)
        self.assertNotIn('system-info', result)
        self.assertNotIn('applications', result)
        self.assertIn('managed-devices', result)
        self.assertIn('purchased-pool-licenses', result)

    def test_gather_subset_exclude_all_only(self):
        """Test '!all' exclusion only"""
        set_module_args(dict(gather_subset=['!all']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        mm.handle_all_keyword()
        mm.filter_excluded_meta_facts()
        result = mm.filter_excluded_facts()

        self.assertEqual(len(result), 0)

    def test_gather_subset_multiple_explicit_facts(self):
        """Test multiple explicit facts without 'all' keyword"""
        set_module_args(dict(
            gather_subset=['applications', 'vlans', 'system-info']
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value={
            'applications': [],
            'vlans': [],
            'system_info': {}
        })

        result = mm.exec_module()

        self.assertTrue(result['changed'])


class TestModuleIdempotency(unittest.TestCase):
    """Test idempotent behavior of the module"""
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigiq_device_info.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_repeated_fact_gathering_idempotent(self):
        """Test that repeated fact gathering returns identical results"""
        set_module_args(dict(gather_subset=['applications']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        tm = ApplicationsFactManager(module=module, client=Mock())
        mm = ModuleManager(module=module)
        mm.get_manager = Mock(return_value=tm)
        tm.client.get.return_value = dict(code=200, contents=load_fixture('load_bigiq_app.json'))

        result1 = mm.exec_module()

        # Reset and gather again
        tm.client.get.return_value = dict(code=200, contents=load_fixture('load_bigiq_app.json'))

        result2 = mm.exec_module()

        # Both should have applications data (results will be marked changed both times due to module design)
        self.assertIn('applications', result1)
        self.assertIn('applications', result2)
        self.assertEqual(len(result1['applications']), len(result2['applications']))
