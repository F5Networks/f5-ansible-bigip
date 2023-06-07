# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_device_info
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info import (
    GtmServersParameters, VirtualServersParameters, ArgumentSpec, ModuleManager, ApmAccessProfileFactManager,
    ApmAccessPolicyFactManager, As3FactManager, AsmPolicyStatsFactManager, AsmPolicyFactManager,
    AsmServerTechnologyFactManager, AsmSignatureSetsFactManager, ClientSslProfilesFactManager, CFEFactManager,
    DevicesFactManager, DeviceGroupsFactManager, DOFactManager, ExternalMonitorsFactManager,
    FastHttpProfilesFactManager, FastL4ProfilesFactManager, GatewayIcmpMonitorsFactManager, GtmAPoolsFactManager,
    GtmServersFactManager, GtmAWideIpsFactManager, GtmAaaaPoolsFactManager, GtmAaaaWideIpsFactManager,
    GtmCnamePoolsFactManager, GtmCnameWideIpsFactManager, GtmMxPoolsFactManager, GtmMxWideIpsFactManager,
    GtmNaptrPoolsFactManager, GtmNaptrWideIpsFactManager, GtmSrvPoolsFactManager, GtmSrvWideIpsFactManager,
    GtmTopologyRegionFactManager, HttpMonitorsFactManager, HttpsMonitorsFactManager, HttpProfilesFactManager,
    IappServicesFactManager, IapplxPackagesFactManager, IcmpMonitorsFactManager, InterfacesFactManager,
    InternalDataGroupsFactManager, IrulesFactManager, LicenseFactManager, LtmPoolsFactManager, LtmPolicyFactManager,
    ManagementRouteFactManager, NodesFactManager, OneConnectProfilesFactManager, PartitionFactManager,
    ProvisionInfoFactManager, RouteDomainFactManager, RemoteSyslogFactManager, SelfIpsFactManager,
    ServerSslProfilesFactManager, SoftwareVolumesFactManager, SoftwareImagesFactManager, SoftwareHotfixesFactManager,
    SslCertificatesFactManager, SslKeysFactManager, SyncStatusFactManager, SystemDbFactManager, SystemInfoFactManager,
    TSFactManager, TcpMonitorsFactManager, TcpHalfOpenMonitorsFactManager, TcpProfilesFactManager,
    TrafficGroupsFactManager, TrunksFactManager, UCSFactManager, UsersFactManager, UdpProfilesFactManager,
    VcmpGuestsFactManager, VirtualAddressesFactManager, VirtualServersFactManager, VlansFactManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.urls import parseStats

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import Mock, patch, MagicMock
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


def fake_read_profiles(collection):
    result = [x['name'] for x in collection.get('items')]
    return result


class TestApmManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['apm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_apm_policies_facts(self, *args):
        set_module_args(dict(
            gather_subset=['apm-access-policies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ApmAccessPolicyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_access_policies.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertListEqual(
            results['apm_access_policies'], [{'full_path': '/Common/foo_access', 'name': 'foo_access'}]
        )

    def test_get_apm_policies_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['apm-access-policies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ApmAccessPolicyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=503, contents='server error'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_get_apm_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['apm-access-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ApmAccessProfileFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_access_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertListEqual(
            results['apm_access_profiles'],
            [{'full_path': '/Common/access', 'name': 'access'},
             {'access_policy': '/Common/foo_access', 'full_path': '/Common/foo_access', 'name': 'foo_access'}]
        )

    def test_get_apm_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['apm-access-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ApmAccessProfileFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=503, contents='server error'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])


class TestAsmManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['asm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_asm_policies_stats_facts(self, *args):
        set_module_args(dict(
            gather_subset=['asm-policy-stats']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmPolicyStatsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_asm_policies.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(
            results['asm_policy_stats'],
            {'policies': 2, 'parent_policies': 0, 'policies_pending_changes': 0, 'policies_active': 2,
             'policies_attached': 2, 'policies_inactive': 0, 'policies_unattached': 0}
        )

    def test_get_asm_policies_stats_facts_empty_results(self, *args):
        set_module_args(dict(
            gather_subset=['asm-policy-stats']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmPolicyStatsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()
        self.assertTrue(results['queried'])
        self.assertDictEqual(results['asm_policy_stats'], {})

    def test_get_asm_policies_stats_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['asm-policy-stats']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmPolicyStatsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=503, contents='server error'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_get_asm_policies_facts(self, *args):
        set_module_args(dict(
            gather_subset=['asm-policies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmPolicyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_asm_policies.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['asm_policies']) == 2)
        self.assertEqual(results['asm_policies'][0]['name'], 'scenario1')
        self.assertEqual(results['asm_policies'][0]['policy_id'], '41UMLL7yDtzoa0000Wimzw')
        self.assertEqual(results['asm_policies'][0]['active'], 'yes')
        self.assertEqual(results['asm_policies'][0]['protocol_independent'], 'no')
        self.assertEqual(results['asm_policies'][0]['has_parent'], 'no')
        self.assertEqual(results['asm_policies'][0]['type'], 'security')
        self.assertEqual(results['asm_policies'][0]['full_path'], '/Common/scenario1')
        self.assertListEqual(results['asm_policies'][0]['virtual_servers'], ['/Common/foo1'])
        self.assertListEqual(results['asm_policies'][0]['allowed_response_codes'], [400, 401, 404, 407, 417, 503])
        self.assertEqual(results['asm_policies'][1]['name'], 'scenario4')
        self.assertEqual(results['asm_policies'][1]['policy_id'], '-rJ0Aa2BUjq527-JBwBlVw')
        self.assertEqual(results['asm_policies'][1]['active'], 'yes')
        self.assertEqual(results['asm_policies'][1]['protocol_independent'], 'no')
        self.assertEqual(results['asm_policies'][1]['has_parent'], 'no')
        self.assertEqual(results['asm_policies'][1]['type'], 'security')
        self.assertEqual(results['asm_policies'][1]['full_path'], '/Common/scenario4')
        self.assertListEqual(results['asm_policies'][1]['virtual_servers'], [])
        self.assertListEqual(results['asm_policies'][1]['allowed_response_codes'], [400, 401, 404, 407, 417, 503])

    def test_get_asm_policies_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['asm-policies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmPolicyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=503, contents='server error'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_get_asm_tech_facts(self, *args):
        set_module_args(dict(
            gather_subset=['asm-server-technologies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmServerTechnologyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_asm_server_tech.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['asm_server_technologies']) == 73)
        self.assertTrue(results['asm_server_technologies'][0]['server_technology_name'] == 'ASP')
        self.assertTrue(results['asm_server_technologies'][-1]['server_technology_name'] == 'jQuery')

    def test_get_asm_tech_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['asm-server-technologies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmServerTechnologyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=503, contents='server error'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_get_asm_sig_sets_facts(self, *args):
        set_module_args(dict(
            gather_subset=['asm-signature-sets']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmSignatureSetsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_asm_sig_set_fragment.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertListEqual(
            results['asm_signature_sets'],
            [{'name': 'Apache/NCSA HTTP Server Signatures (High/Medium Accuracy)', 'id': 'Qv3YrNzr8DG9xMgRxJwlBQ',
              'type': 'filter-based', 'category': 'User-defined', 'is_user_defined': 'yes',
              'assign_to_policy_by_default': 'no', 'default_alarm': 'no', 'default_block': 'no', 'default_learn': 'no'},
             {'name': 'Node.js Signatures (High/Medium Accuracy)', 'id': 'fmwqhS5kepbRzuFRcOKdkQ',
              'type': 'filter-based', 'category': 'User-defined', 'is_user_defined': 'yes',
              'assign_to_policy_by_default': 'no', 'default_alarm': 'no', 'default_block': 'no', 'default_learn': 'no'}]
        )

    def test_get_asm_sig_sets_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['asm-signature-sets']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = AsmSignatureSetsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=503, contents='server error'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])


class TestAtcManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = []
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True
        self.p3 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.packages_installed')
        self.m3 = self.p3.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()

    def test_get_as3_facts(self, *args):
        set_module_args(dict(
            gather_subset=['as3']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = As3FactManager(module=module, client=MagicMock())
        tm.installed_packages = ['as3']
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_as3_declare_facts.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(results['as3_config'])
        self.assertIn('declaration', results['as3_config'][0].keys())

    def test_get_as3_facts_empty(self, *args):
        set_module_args(dict(
            gather_subset=['as3']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = As3FactManager(module=module, client=MagicMock())
        tm.installed_packages = ['as3']
        tm.client.get = Mock(return_value=dict(code=204, contents={}))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['as3_config'])

    def test_get_as3_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['as3']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = As3FactManager(module=module, client=MagicMock())
        tm.installed_packages = ['as3']
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_do_facts(self, *args):
        set_module_args(dict(
            gather_subset=['do']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = DOFactManager(module=module, client=MagicMock())
        tm.installed_packages = ['do']
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_do_declaration_facts.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(results['do_config'])
        self.assertIn('declaration', results['do_config'][0].keys())

    def test_get_do_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['do']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = DOFactManager(module=module, client=MagicMock())
        tm.installed_packages = ['do']
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_cfe_facts(self, *args):
        set_module_args(dict(
            gather_subset=['cfe']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = CFEFactManager(module=module, client=MagicMock())
        tm.installed_packages = ['cfe']
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_cfe_declaration_facts.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(results['cfe_config'])
        self.assertIn('declaration', results['cfe_config'][0].keys())

    def test_get_cfe_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['cfe']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = CFEFactManager(module=module, client=MagicMock())
        tm.installed_packages = ['cfe']
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_ts_facts(self, *args):
        set_module_args(dict(
            gather_subset=['ts']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TSFactManager(module=module, client=MagicMock())
        tm.installed_packages = ['ts']
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_ts_declare_facts.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(results['ts_config'])
        self.assertIn('declaration', results['ts_config'][0].keys())

    def test_get_ts_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['cfe']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TSFactManager(module=module, client=MagicMock())
        tm.installed_packages = ['ts']
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestGtmManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['gtm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_gtm_topology_region_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-topology-regions']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmTopologyRegionFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_topology_regions.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertListEqual(
            results['gtm_topology_regions'],
            [{'name': 'fake_region', 'full_path': '/Common/fake_region',
              'region_members': [{'continent': 'AN'}, {'isp': '/Common/AOL'}, {'subnet': '191.1.1.0/24'}]}]
        )

    def test_get_gtm_topology_region_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-topology-regions']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmTopologyRegionFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_a_pool_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-a-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_a_pools.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_a_pools']) == 2)
        self.assertTrue(results['gtm_a_pools'][0]['full_path'] == '/Common/fake_a_pool')
        self.assertDictEqual(
            results['gtm_a_pools'][0]['members'][0],
            {'name': 'foo_gtm_server:foo', 'partition': 'Common', 'enabled': 'yes', 'limitMaxBps': 0,
             'limitMaxBpsStatus': 'disabled', 'limitMaxConnections': 0, 'limitMaxConnectionsStatus': 'disabled',
             'limitMaxPps': 0, 'limitMaxPpsStatus': 'disabled', 'monitor': 'default', 'ratio': 1, 'disabled': 'no',
             'member_order': 0}
        )

    def test_get_gtm_a_pool_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-a-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_aaaa_pool_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-aaaa-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAaaaPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_aaaa_pools.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_aaaa_pools']) == 1)
        self.assertTrue(results['gtm_aaaa_pools'][0]['full_path'] == '/Common/fake_aaaa_pool')

    def test_get_gtm_aaaa_pool_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-aaaa-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAaaaPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_cname_pool_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-cname-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmCnamePoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_cname_pools.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_cname_pools']) == 1)
        self.assertTrue(results['gtm_cname_pools'][0]['full_path'] == '/Common/fake_cname_pool')

    def test_get_gtm_cname_pool_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-cname-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmCnamePoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_mx_pool_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-mx-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmMxPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_mx_pools.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_mx_pools']) == 1)
        self.assertTrue(results['gtm_mx_pools'][0]['full_path'] == '/Common/fake_mx_pool')

    def test_get_gtm_mx_pool_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-mx-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmMxPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_naptr_pool_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-naptr-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmNaptrPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_naptr_pools.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_naptr_pools']) == 1)
        self.assertTrue(results['gtm_naptr_pools'][0]['full_path'] == '/Common/fake_naptr_pool')

    def test_get_gtm_naptr_pool_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-naptr-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmNaptrPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_srv_pool_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-srv-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmSrvPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_srv_pools.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_srv_pools']) == 1)
        self.assertTrue(results['gtm_srv_pools'][0]['full_path'] == '/Common/fake_srv_pool')

    def test_get_gtm_srv_pool_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-naptr-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmSrvPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_servers_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmServersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_servers.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_gtm_vs_stats.json')),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_servers']) == 1)
        self.assertTrue(results['gtm_servers'][0]['full_path'] == '/Common/foo_gtm_server')
        self.assertTrue(len(results['gtm_servers'][0]['virtual_servers']) == 3)
        self.assertTrue(tm.client.get.call_count == 5)

    def test_get_gtm_servers_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmServersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_gtm_server_params_read_methods_failures(self):
        fv = GtmServersParameters(client=Mock(), params=dict())
        fv.client.get = Mock(return_value=dict(code=404, contents='not found'))

        with self.assertRaises(F5ModuleError) as err:
            fv._read_virtual_stats_from_device('foo')
        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_a_wideip_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-a-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_a_wideips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_a_wide_ips']) == 1)
        self.assertListEqual(
            results['gtm_a_wide_ips'],
            [{'full_path': '/Common/fake.wide-a.net', 'enabled': 'yes', 'failure_rcode': 'noerror',
              'failure_rcode_response': 'no', 'failure_rcode_ttl': 0, 'last_resort_pool': '',
              'minimal_response': 'enabled', 'name': 'fake.wide-a.net', 'persist_cidr_ipv4': 32,
              'persist_cidr_ipv6': 128, 'pool_lb_mode': 'round-robin', 'ttl_persistence': 3600, 'pools': []}]
        )

    def test_get_gtm_a_wideip_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-a-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_aaaa_wideip_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-aaaa-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAaaaWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_aaaa_wideips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_aaaa_wide_ips']) == 1)
        self.assertListEqual(
            results['gtm_aaaa_wide_ips'],
            [{'full_path': '/Common/fake.wide-aaaa.net', 'enabled': 'yes', 'failure_rcode': 'noerror',
              'failure_rcode_response': 'no', 'failure_rcode_ttl': 0, 'last_resort_pool': '',
              'minimal_response': 'enabled', 'name': 'fake.wide-aaaa.net', 'persist_cidr_ipv4': 32,
              'persist_cidr_ipv6': 128, 'pool_lb_mode': 'ratio', 'ttl_persistence': 3600, 'pools': []}]
        )

    def test_get_gtm_aaaa_wideip_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-aaaa-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmAaaaWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_cname_wideip_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-cname-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmCnameWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_cname_wideips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_cname_wide_ips']) == 1)
        self.assertListEqual(
            results['gtm_cname_wide_ips'],
            [{'full_path': '/Common/fake.wide-cname.net', 'enabled': 'yes', 'failure_rcode': 'noerror',
              'failure_rcode_response': 'no', 'failure_rcode_ttl': 0, 'last_resort_pool': '',
              'minimal_response': 'enabled', 'name': 'fake.wide-cname.net', 'persist_cidr_ipv4': 32,
              'persist_cidr_ipv6': 128, 'pool_lb_mode': 'topology', 'ttl_persistence': 3600, 'pools': []}]
        )

    def test_get_gtm_cname_wideip_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-cname-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmCnameWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_mx_wideip_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-mx-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmMxWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_mx_wideips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_mx_wide_ips']) == 1)
        self.assertListEqual(
            results['gtm_mx_wide_ips'],
            [{'full_path': '/Common/fake.wide-mx.net', 'enabled': 'yes', 'failure_rcode': 'noerror',
              'failure_rcode_response': 'no', 'failure_rcode_ttl': 0, 'last_resort_pool': '',
              'minimal_response': 'enabled', 'name': 'fake.wide-mx.net', 'persist_cidr_ipv4': 32,
              'persist_cidr_ipv6': 128, 'pool_lb_mode': 'global-availability', 'ttl_persistence': 3600, 'pools': []}]
        )

    def test_get_gtm_mx_wideip_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-mx-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmMxWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_naptr_wideip_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-naptr-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmNaptrWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_naptr_wideips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_naptr_wide_ips']) == 1)
        self.assertListEqual(
            results['gtm_naptr_wide_ips'],
            [{'full_path': '/Common/fake.wide-naptr.net', 'enabled': 'yes', 'failure_rcode': 'noerror',
              'failure_rcode_response': 'no', 'failure_rcode_ttl': 0, 'last_resort_pool': '',
              'minimal_response': 'enabled', 'name': 'fake.wide-naptr.net', 'persist_cidr_ipv4': 32,
              'persist_cidr_ipv6': 128, 'pool_lb_mode': 'round-robin', 'ttl_persistence': 3600, 'pools': []}]
        )

    def test_get_gtm_naptr_wideip_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-naptr-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmNaptrWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_gtm_srv_wideip_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-srv-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmSrvWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gtm_srv_wideips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['gtm_srv_wide_ips']) == 1)
        self.assertListEqual(
            results['gtm_srv_wide_ips'],
            [{'full_path': '/Common/fake.wide-srv.net', 'enabled': 'yes', 'failure_rcode': 'noerror',
              'failure_rcode_response': 'no', 'failure_rcode_ttl': 0, 'last_resort_pool': '',
              'minimal_response': 'enabled', 'name': 'fake.wide-srv.net', 'persist_cidr_ipv4': 32,
              'persist_cidr_ipv6': 128, 'pool_lb_mode': 'round-robin', 'ttl_persistence': 3600, 'pools': []}]
        )

    def test_get_gtm_srv_wideip_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gtm-srv-wide-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GtmSrvWideIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])


class TestIappManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = []
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_iapp_services_facts(self, *args):
        set_module_args(dict(
            gather_subset=['iapp-services']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IappServicesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_iapp_services_facts.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['iapp_services']) == 1)

    def test_get_iapp_services_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['iapp-services']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IappServicesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_iapplx_packages_facts(self, *args):
        set_module_args(dict(
            gather_subset=['iapplx-packages']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IapplxPackagesFactManager(module=module, client=MagicMock())
        tm.client.post = Mock(return_value=dict(code=200, contents=load_fixture('reply_iapp_pkg_query.json')))
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_task_query_iappkg.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('iapplx_packages', results)
        self.assertTrue(results['iapplx_packages'])

    def test_get_iapplx_packages_facts_query_raises(self, *args):
        set_module_args(dict(
            gather_subset=['iapplx-packages']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IapplxPackagesFactManager(module=module, client=MagicMock())
        tm.client.post = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(tm.client.post.called)

    def test_get_iapplx_packages_facts_task_raises(self, *args):
        set_module_args(dict(
            gather_subset=['iapplx-packages']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IapplxPackagesFactManager(module=module, client=MagicMock())
        tm.client.post = Mock(return_value=dict(code=200, contents=load_fixture('reply_iapp_pkg_query.json')))
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(tm.client.post.called)
        self.assertTrue(tm.client.get.called)
        self.assertTrue(tm.client.get.call_count == 1)

    def test_get_iapplx_packages_facts_get_finished_task_raises(self, *args):
        set_module_args(dict(
            gather_subset=['iapplx-packages']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IapplxPackagesFactManager(module=module, client=MagicMock())
        tm.client.post = Mock(return_value=dict(code=200, contents=load_fixture('reply_iapp_pkg_query.json')))
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_task_query_iappkg.json')),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(tm.client.post.called)
        self.assertTrue(tm.client.get.called)
        self.assertTrue(tm.client.get.call_count == 2)

    def test_get_iapplx_packages_facts_task_failed_raises(self, *args):
        set_module_args(dict(
            gather_subset=['iapplx-packages']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        response = {
            "operation": "QUERY",
            "id": "82d4514c-afd2-4b4f-909f-e231d16b31c2",
            "status": "FAILED",
            "startTime": "2023-03-21T12:53:37.723-0700",
            "endTime": "2023-03-21T12:53:37.767-0700"
        }

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IapplxPackagesFactManager(module=module, client=MagicMock())
        tm.client.post = Mock(return_value=dict(code=200, contents=load_fixture('reply_iapp_pkg_query.json')))
        tm.client.get = Mock(return_value=dict(code=200, contents=response))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('An error occurred querying iAppLX packages.', err.exception.args[0])
        self.assertTrue(tm.client.post.called)
        self.assertTrue(tm.client.get.called)
        self.assertTrue(tm.client.get.call_count == 1)


class TestLtmFactsManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm', 'gtm', 'asm', 'vcmp']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_internal_dg_facts(self, *args):
        set_module_args(dict(
            gather_subset=['internal-data-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = InternalDataGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_internal_dgs.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('internal_data_groups', results)
        self.assertTrue(len(results['internal_data_groups']) == 15)
        self.assertDictEqual(
            results['internal_data_groups'][0],
            {'full_path': '/Common/ServiceDiscovery/tasks', 'name': 'tasks', 'type': 'string'}
        )
        self.assertDictEqual(
            results['internal_data_groups'][13],
            {'full_path': '/Common/private_net', 'name': 'private_net', 'type': 'ip',
             'records': [{'name': '10.0.0.0/8', 'data': ''}, {'name': '172.16.0.0/12', 'data': ''},
                         {'name': '192.168.0.0/16', 'data': ''}]
             }
        )

    def test_get_internal_dg_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['internal-data-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = InternalDataGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_irules_facts(self, *args):
        set_module_args(dict(
            gather_subset=['irules']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IrulesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_irules.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('irules', results)
        self.assertTrue(len(results['irules']) == 15)

    def test_get_irules_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['irules']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IrulesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_ltm_pools_facts(self, *args):
        set_module_args(dict(
            gather_subset=['ltm-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LtmPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_pools.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_ltm_pool_members.json')),
            dict(code=200, contents=load_fixture('load_ltm_pool_stats.json')),

        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(tm.client.get.call_count == 4)
        self.assertIn('ltm_pools', results)

    def test_get_ltm_pools_facts_stats_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ltm-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LtmPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_pools.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_ltm_pool_members.json')),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertTrue(tm.client.get.call_count == 4)
        self.assertIn('access denied', err.exception.args[0])

    def test_get_ltm_pools_facts_members_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ltm-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LtmPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_pools.json')),
            dict(code=200, contents={}),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertTrue(tm.client.get.call_count == 3)
        self.assertIn('access denied', err.exception.args[0])

    def test_get_ltm_pools_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ltm-pools']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LtmPoolsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_ltm_policies_facts(self, *args):
        set_module_args(dict(
            gather_subset=['ltm-policies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LtmPolicyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_policies.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('ltm_policies', results)
        self.assertDictEqual(
            results['ltm_policies'][0],
            {'full_path': '/Common/foo', 'name': 'foo', 'status': 'published', 'description': 'foo is the name',
             'strategy': '/Common/first-match', 'rules': [{'name': 'bar', 'description': 'description', 'ordinal': 0,
                                                           'conditions': [{'case_insensitive': 'yes', 'remote': 'yes',
                                                                           'present': 'yes', 'http_uri': 'yes',
                                                                           'request': 'yes', 'values': ['foo'],
                                                                           'all': 'yes'},
                                                                          {'case_insensitive': 'yes', 'remote': 'yes',
                                                                           'present': 'yes', 'request': 'yes',
                                                                           'values': ['GET'], 'all': 'yes'}],
                                                           'actions': [
                                                               {'forward': True, 'node': '1.1.1.1', 'request': True,
                                                                'select': True},
                                                               {'expression': 'GET', 'tmName': 'fooget',
                                                                'request': True, 'setVariable': True, 'tcl': True}]}],
             'requires': ['http'], 'controls': ['forwarding']}
        )

    def test_get_ltm_policies_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ltm-policies']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LtmPolicyFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_nodes_facts(self, *args):
        set_module_args(dict(
            gather_subset=['nodes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = NodesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_nodes.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_ltm_node_stats.json')),
            dict(code=200, contents={}),

        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('nodes', results)
        self.assertDictEqual(
            results['nodes'][0],
            {'full_path': '/Common/7.3.67.8', 'name': '7.3.67.8', 'ratio': 1, 'description': 'ipv4 node',
             'connection_limit': 0, 'address': '7.3.67.8', 'dynamic_ratio': 1, 'rate_limit': 0,
             'monitor_status': 'down', 'session_status': 'enabled', 'availability_status': 'offline',
             'enabled_status': 'enabled',
             'status_reason': '/Common/gateway_icmp: No successful responses received before deadline. '
                              '@2023/03/08 11:17:36. /Common/icmp: No successful responses received before '
                              'deadline. @2023/03/08 11:17:36. ',
             'monitor_rule': 'min 1 of /Common/gateway_icmp /Common/icmp',
             'monitors': ['/Common/gateway_icmp', '/Common/icmp'], 'monitor_type': 'm_of_n', 'fqdn_auto_populate': 'no',
             'fqdn_address_type': 'ipv4', 'fqdn_up_interval': 3600, 'fqdn_down_interval': 5}
        )
        self.assertDictEqual(
            results['nodes'][1],
            {'full_path': '/Common/foo.bar.com', 'name': 'foo.bar.com', 'ratio': 1, 'description': 'fqdn node',
             'connection_limit': 0, 'address': 'any6', 'dynamic_ratio': 1, 'rate_limit': 0, 'monitors': [],
             'monitor_type': 'and_list', 'fqdn_name': 'foo.bar.com', 'fqdn_auto_populate': 'no',
             'fqdn_address_type': 'ipv4', 'fqdn_up_interval': 3600, 'fqdn_down_interval': 5}
        )

    def test_get_nodes_facts_stats_raises(self, *args):
        set_module_args(dict(
            gather_subset=['nodes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = NodesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_nodes.json')),
            dict(code=200, contents={}),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertTrue(tm.client.get.call_count == 3)
        self.assertIn('access denied', err.exception.args[0])

    def test_get_nodes_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['nodes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = NodesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestMonitorFactManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_external_monitors_facts(self, *args):
        set_module_args(dict(
            gather_subset=['external-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ExternalMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ext_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('external_monitors', results)
        self.assertDictEqual(
            results['external_monitors'][0],
            {'full_path': '/Common/external', 'name': 'external', 'destination': '*:*', 'interval': 5,
             'manual_resume': 'no', 'time_until_up': 0, 'timeout': 16, 'up_interval': 0}
        )

    def test_get_external_monitors_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['external-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ExternalMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_gw_icmp_monitors_facts(self, *args):
        set_module_args(dict(
            gather_subset=['gateway-icmp-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GatewayIcmpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_gw_icmp_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('gateway_icmp_monitors', results)
        self.assertDictEqual(
            results['gateway_icmp_monitors'][0],
            {'full_path': '/Common/gateway_icmp', 'name': 'gateway_icmp', 'adaptive': 'no',
             'adaptive_divergence_type': 'relative', 'adaptive_divergence_value': 25, 'adaptive_limit': 200,
             'adaptive_sampling_timespan': 300, 'destination': '*:*', 'interval': 5, 'manual_resume': 'no',
             'time_until_up': 0, 'timeout': 16, 'transparent': 'no', 'up_interval': 0}
        )

    def test_get_gw_icmp_monitors_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['gateway-icmp-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = GatewayIcmpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_http_monitors_facts(self, *args):
        set_module_args(dict(
            gather_subset=['http-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = HttpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_http_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('http_monitors', results)
        self.assertTrue(len(results['http_monitors']) == 2)
        self.assertDictEqual(
            results['http_monitors'][0],
            {'full_path': '/Common/http', 'name': 'http', 'adaptive': 'no', 'adaptive_divergence_type': 'relative',
             'adaptive_divergence_value': 25, 'adaptive_limit': 200, 'adaptive_sampling_timespan': 300,
             'destination': '*:*', 'interval': 5, 'ip_dscp': 0, 'manual_resume': 'no', 'reverse': 'no',
             'send_string': 'GET /\\r\\n', 'time_until_up': 0, 'timeout': 16, 'transparent': 'no', 'up_interval': 0}
        )

    def test_get_http_monitors_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['http-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = HttpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_https_monitors_facts(self, *args):
        set_module_args(dict(
            gather_subset=['https-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = HttpsMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_https_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('https_monitors', results)
        self.assertTrue(len(results['https_monitors']) == 3)
        self.assertDictEqual(
            results['https_monitors'][0],
            {'full_path': '/Common/https', 'name': 'https', 'adaptive': 'no', 'adaptive_divergence_type': 'relative',
             'adaptive_divergence_value': 25, 'adaptive_limit': 200, 'adaptive_sampling_timespan': 300,
             'destination': '*:*', 'interval': 5, 'ip_dscp': 0, 'manual_resume': 'no', 'reverse': 'no',
             'send_string': 'GET /\\r\\n', 'time_until_up': 0, 'timeout': 16, 'transparent': 'no', 'up_interval': 0}
        )

    def test_get_https_monitors_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['https-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = HttpsMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_icmp_monitors_facts(self, *args):
        set_module_args(dict(
            gather_subset=['icmp-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IcmpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_icmp_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('icmp_monitors', results)
        self.assertDictEqual(
            results['icmp_monitors'][0],
            {'full_path': '/Common/icmp', 'name': 'icmp', 'adaptive': 'no', 'adaptive_divergence_type': 'relative',
             'adaptive_divergence_value': 25, 'adaptive_limit': 200, 'adaptive_sampling_timespan': 300,
             'destination': '*', 'interval': 5, 'manual_resume': 'no', 'time_until_up': 0, 'timeout': 16,
             'transparent': 'no', 'up_interval': 0}
        )

    def test_get_icmp_monitors_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['icmp-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = IcmpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_tcp_half_open_monitor_facts(self, *args):
        set_module_args(dict(
            gather_subset=['tcp-half-open-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TcpHalfOpenMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_tcp_half_open_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('tcp_half_open_monitors', results)
        self.assertDictEqual(
            results['tcp_half_open_monitors'][0],
            {'full_path': '/Common/tcp_half_open', 'name': 'tcp_half_open', 'destination': '*:*', 'interval': 5,
             'manual_resume': 'no', 'time_until_up': 0, 'timeout': 16, 'transparent': 'no', 'up_interval': 0}
        )

    def test_get_tcp_half_open_monitor_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['tcp-half-open-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TcpHalfOpenMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_tcp_monitor_facts(self, *args):
        set_module_args(dict(
            gather_subset=['tcp-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TcpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_tcp_monitors.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('tcp_monitors', results)
        self.assertDictEqual(
            results['tcp_monitors'][0],
            {'full_path': '/Common/tcp', 'name': 'tcp', 'adaptive': 'no', 'adaptive_divergence_type': 'relative',
             'adaptive_divergence_value': 25, 'adaptive_limit': 200, 'adaptive_sampling_timespan': 300,
             'destination': '*:*', 'interval': 5, 'ip_dscp': 0, 'manual_resume': 'no', 'reverse': 'no',
             'time_until_up': 0, 'timeout': 16, 'transparent': 'no', 'up_interval': 0}
        )

    def test_get_tcp_monitor_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['tcp-monitors']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TcpMonitorsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestNetworkFactsManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_mgmt_route_facts(self, *args):
        set_module_args(dict(
            gather_subset=['management-routes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ManagementRouteFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_mgmt_route.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('management_routes', results)
        self.assertListEqual(
            results['management_routes'],
            [{'full_path': '/Common/default', 'name': 'default', 'description': 'configured-by-dhcp',
              'gateway': '10.144.75.254', 'mtu': 0, 'network': 'default'}]
        )

    def test_get_mgmt_route_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['management-routes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ManagementRouteFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_route_domain_facts(self, *args):
        set_module_args(dict(
            gather_subset=['route-domains']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = RouteDomainFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_route_domains.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('route_domains', results)
        self.assertDictEqual(
            results['route_domains'][0],
            {'name': '0', 'id': 0, 'full_path': '/Common/0', 'connection_limit': 0, 'strict': 'yes',
             'vlans': ['/Common/http-tunnel', '/Common/socks-tunnel', '/Common/alice', '/Common/foo1']}
        )

    def test_get_route_domain_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['route-domains']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = RouteDomainFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_selfips_facts(self, *args):
        set_module_args(dict(
            gather_subset=['self-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SelfIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_self_ips.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('self_ips', results)
        self.assertDictEqual(
            results['self_ips'][0],
            {'full_path': '/Common/bar', 'name': 'bar', 'address': '192.2.1.1', 'netmask': '255.255.255.0',
             'netmask_cidr': 24, 'floating': 'no', 'traffic_group': '/Common/traffic-group-local-only',
             'vlan': '/Common/foo1', 'allow_access_list': 'all', 'traffic_group_inherited': 'no'}
        )

        self.assertDictEqual(
            results['self_ips'][1],
            {'full_path': '/Common/foo', 'name': 'foo', 'address': '192.1.1.1', 'netmask': '255.255.255.0',
             'netmask_cidr': 24, 'floating': 'no', 'traffic_group': '/Common/traffic-group-local-only',
             'vlan': '/Common/alice', 'allow_access_list': ['default'], 'traffic_group_inherited': 'no'}
        )

    def test_get_selfips_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['self-ips']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SelfIpsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_trunk_facts_with_stats(self, *args):
        set_module_args(dict(
            gather_subset=['trunks']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TrunksFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_trunks.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_trunk_stats.json')),
            dict(code=200, contents={}),
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(tm.client.get.call_count == 4)
        self.assertDictEqual(
            results['trunks'][0],
            {'full_path': 'foo', 'name': 'foo', 'media_speed': '10000', 'lacp_mode': 'active', 'lacp_enabled': 'yes',
             'stp_enabled': 'yes', 'operational_member_count': 1, 'link_selection_policy': 'maximum-bandwidth',
             'lacp_timeout': 'long', 'interfaces': ['1.3'], 'distribution_hash': 'dst-mac',
             'configured_member_count': 1}
        )
        self.assertDictEqual(
            results['trunks'][1]['stats'],
            {'counters': {'bitsIn': 0, 'bitsOut': 0, 'collisions': 0, 'dropsIn': 0, 'dropsOut': 0, 'errorsIn': 0,
                          'errorsOut': 0}, 'tmName': 'test_trunk', 'operBw': 0, 'status': 'uninit'}
        )

    def test_get_trunk_facts_stats_raises(self, *args):
        set_module_args(dict(
            gather_subset=['trunks']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TrunksFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_trunks.json')),
            dict(code=200, contents={}),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(tm.client.get.call_count == 3)

    def test_get_trunk_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['trunks']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TrunksFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_vlan_facts_with_stats(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VlansFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_vlans.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_vlan_stats.json')),
            dict(code=200, contents={}),
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(tm.client.get.call_count == 4)
        self.assertDictEqual(
            results['vlans'][0],
            {'full_path': '/Common/alice', 'name': 'alice', 'auto_lasthop': 'default',
             'cmp_hash_algorithm': 'default', 'failsafe_action': 'failover-restart-tm',
             'failsafe_enabled': 'no', 'failsafe_timeout': 90, 'if_index': 912, 'learning_mode': 'enable-forward',
             'interfaces': [{'name': '1.2', 'full_path': '1.2', 'tagged': 'no'}], 'mtu': 1500, 'sflow_poll_interval': 0,
             'sflow_poll_interval_global': 'yes', 'sflow_sampling_rate': 0, 'sflow_sampling_rate_global': 'yes',
             'source_check_enabled': 'disabled', 'true_mac_address': 'fa:16:3e:df:7a:c7', 'tag': 3605}
        )

        self.assertDictEqual(
            results['vlans'][1],
            {'full_path': '/Common/foo1', 'name': 'foo1', 'auto_lasthop': 'default', 'cmp_hash_algorithm': 'default',
             'failsafe_action': 'failover-restart-tm', 'failsafe_enabled': 'no', 'failsafe_timeout': 90,
             'if_index': 896, 'learning_mode': 'enable-forward',
             'interfaces': [{'name': '1.1', 'full_path': '1.1', 'tagged': 'yes'}], 'mtu': 1500,
             'sflow_poll_interval': 0, 'sflow_poll_interval_global': 'no', 'sflow_sampling_rate': 0,
             'sflow_sampling_rate_global': 'no', 'source_check_enabled': 'disabled'}
        )

    def test_get_vlan_facts_stats_raises(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VlansFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_vlans.json')),
            dict(code=200, contents={}),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(tm.client.get.call_count == 3)

    def test_get_vlan_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VlansFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestProfilesFactsManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_clientssl_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['client-ssl-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ClientSslProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_clientssl_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('client_ssl_profiles', results)
        self.assertTrue(len(results['client_ssl_profiles']) == 7)
        self.assertDictEqual(
            results['client_ssl_profiles'][0],
            {'full_path': '/Common/clientssl', 'name': 'clientssl', 'alert_timeout': 0, 'allow_non_ssl': 'no',
             'authenticate_depth': 9, 'authenticate_frequency': 'once', 'cache_size': 262144, 'cache_timeout': 3600,
             'certificate_file': '/Common/default.crt', 'key_file': '/Common/default.key', 'ciphers': ['DEFAULT'],
             'parent': 'none', 'description': 'none', 'modssl_methods': 'no', 'peer_certification_mode': 'ignore',
             'sni_require': 'no', 'sni_default': 'no', 'strict_resume': 'no', 'profile_mode_enabled': 'yes',
             'renegotiation_maximum_record_delay': 0, 'renegotiation_period': 0, 'renegotiation': 'yes',
             'session_ticket': 'no', 'unclean_shutdown': 'yes', 'retain_certificate': 'yes',
             'secure_renegotiation_mode': 'require', 'handshake_timeout': 10,
             'forward_proxy_certificate_extension_include': ['basic-constraints', 'subject-alternative-name'],
             'forward_proxy_certificate_lifespan': 30, 'forward_proxy_lookup_by_ipaddr_port': 'no',
             'forward_proxy_enabled': 'no'}
        )

    def test_get_clientssl_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['client-ssl-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ClientSslProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_fasthttp_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['fasthttp-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = FastHttpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_fasthttp_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('fasthttp_profiles', results)
        self.assertDictEqual(
            results['fasthttp_profiles'][0],
            {'full_path': '/Common/fasthttp', 'name': 'fasthttp', 'client_close_timeout': 5,
             'oneconnect_idle_timeout_override': 0, 'oneconnect_maximum_reuse': 0, 'oneconnect_maximum_pool_size': 2048,
             'oneconnect_minimum_pool_size': 0, 'oneconnect_replenish': 'yes', 'oneconnect_ramp_up_increment': 4,
             'parent': 'none', 'description': 'none', 'force_http_1_0_response': 'no',
             'http_1_1_close_workarounds': 'no', 'idle_timeout': 300, 'insert_xforwarded_for': 'no',
             'maximum_header_size': 32768, 'maximum_requests': 0, 'maximum_segment_size_override': 0,
             'receive_window_size': 0, 'reset_on_timeout': 'yes', 'server_close_timeout': 5, 'server_sack': 'no',
             'server_timestamp': 'no', 'unclean_shutdown': 'disabled'}
        )

    def test_get_fasthttp_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['fasthttp-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = FastHttpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_fastl4_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['fastl4-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = FastL4ProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_fastl4_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('fastl4_profiles', results)
        self.assertTrue(len(results['fastl4_profiles']) == 4)
        self.assertDictEqual(
            results['fastl4_profiles'][0],
            {'full_path': '/Common/apm-forwarding-fastL4', 'name': 'apm-forwarding-fastL4', 'client_timeout': 30,
             'parent': '/Common/fastL4', 'explicit_flow_migration': 'no', 'hardware_syn_cookie': 'no',
             'idle_timeout': 7200, 'dont_fragment_flag': 'preserve', 'ip_tos_to_client': 'pass-through',
             'ip_tos_to_server': 'pass-through', 'ttl_mode': 'decrement', 'ttl_v4': 255, 'ttl_v6': 64,
             'keep_alive_interval': 0, 'late_binding': 'no', 'link_qos_to_client': 'pass-through',
             'link_qos_to_server': 'pass-through', 'loose_close': 'no', 'loose_init': 'no', 'mss_override': 0,
             'priority_to_client': 'pass-through', 'priority_to_server': 'pass-through', 'pva_acceleration': 'full',
             'pva_dynamic_client_packets': 1, 'pva_dynamic_server_packets': 0, 'pva_flow_aging': 'yes',
             'pva_flow_evict': 'yes', 'pva_offload_dynamic': 'yes', 'pva_offload_state': 'embryonic',
             'reassemble_fragments': 'no', 'receive_window': 0, 'reset_on_timeout': 'yes', 'rtt_from_client': 'no',
             'rtt_from_server': 'no', 'server_sack': 'no', 'server_timestamp': 'no', 'software_syn_cookie': 'no',
             'syn_cookie_enabled': 'yes', 'syn_cookie_mss': 0, 'syn_cookie_whitelist': 'no', 'tcp_close_timeout': 5,
             'generate_init_seq_number': 'no', 'tcp_handshake_timeout': 5, 'strip_sack': 'no',
             'tcp_time_wait_timeout': 0, 'tcp_timestamp_mode': 'preserve', 'tcp_window_scale_mode': 'preserve',
             'timeout_recovery': 'disconnect'}
        )

    def test_get_fastl4_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['fastl4-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = FastL4ProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_http_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['http-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = HttpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_http_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('http_profiles', results)
        self.assertTrue(len(results['http_profiles']) == 3)
        self.assertDictEqual(
            results['http_profiles'][0],
            {'full_path': '/Common/http', 'name': 'http', 'parent': 'none', 'accept_xff': 'no',
             'allow_truncated_redirects': 'no', 'excess_client_headers': 'reject', 'excess_server_headers': 'reject',
             'known_methods': ['CONNECT', 'DELETE', 'GET', 'HEAD', 'LOCK', 'OPTIONS', 'POST', 'PROPFIND', 'PUT',
                               'TRACE', 'UNLOCK'], 'max_header_count': 64, 'max_header_size': 32768, 'max_requests': 0,
             'oversize_client_headers': 'reject', 'oversize_server_headers': 'reject', 'unknown_method': 'allow',
             'default_connect_handling': 'deny', 'hsts_include_subdomains': 'yes', 'hsts_enabled': 'no',
             'insert_xforwarded_for': 'no', 'lws_max_columns': 80, 'onconnect_transformations': 'yes',
             'proxy_mode': 'reverse', 'redirect_rewrite': 'none', 'request_chunking': 'sustain',
             'response_chunking': 'sustain', 'server_agent_name': 'BigIP', 'sflow_poll_interval': 0,
             'sflow_sampling_rate': 0, 'via_request': 'preserve', 'via_response': 'preserve'}
        )

    def test_get_http_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['http-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = HttpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_one_connect_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['oneconnect-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = OneConnectProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_one_connect_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('oneconnect_profiles', results)
        self.assertDictEqual(
            results['oneconnect_profiles'][0],
            {'full_path': '/Common/oneconnect', 'name': 'oneconnect', 'parent': 'none', 'idle_timeout_override': 0,
             'limit_type': 'none', 'max_age': 86400, 'max_reuse': 1000, 'max_size': 10000, 'share_pools': 'no',
             'source_mask': 'any'}
        )

    def test_get_one_connect_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['oneconnect-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = OneConnectProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_tcp_profile_facts(self, *args):
        set_module_args(dict(
            gather_subset=['tcp-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TcpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_tcp_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('tcp_profiles', results)
        self.assertTrue(len(results['tcp_profiles']) == 15)
        self.assertDictEqual(
            results['tcp_profiles'][0],
            {'full_path': '/Common/apm-forwarding-client-tcp', 'name': 'apm-forwarding-client-tcp',
             'parent': '/Common/tcp-legacy', 'abc': 'yes', 'ack_on_push': 'yes', 'auto_proxy_buffer': 'no',
             'auto_receive_window': 'no', 'auto_send_buffer': 'no', 'close_wait': 5, 'congestion_metrics_cache': 'yes',
             'congestion_metrics_cache_timeout': 0, 'congestion_control': 'high-speed', 'deferred_accept': 'no',
             'delay_window_control': 'no', 'delayed_acks': 'yes', 'dsack': 'no', 'early_retransmit': 'no',
             'explicit_congestion_notification': 'no', 'enhanced_loss_recovery': 'no', 'fast_open': 'no',
             'fast_open_cookie_expiration': 21600, 'fin_wait_1': 5, 'fin_wait_2': 300, 'idle_timeout': 300,
             'initial_congestion_window_size': 3, 'initial_receive_window_size': 3, 'dont_fragment_flag': 'pmtu',
             'ip_tos': '0', 'time_to_live': 'proxy', 'time_to_live_v4': 255, 'time_to_live_v6': 64,
             'keep_alive_interval': 60, 'limited_transmit_recovery': 'yes', 'link_qos': '0', 'max_segment_retrans': 8,
             'max_syn_retrans': 3, 'max_segment_size': 1460, 'md5_signature': 'no', 'minimum_rto': 1000,
             'multipath_tcp': 'no', 'mptcp_checksum': 'no', 'mptcp_checksum_verify': 'no', 'mptcp_fallback': 'reset',
             'mptcp_fast_join': 'no', 'mptcp_idle_timeout': 300, 'mptcp_join_max': 5, 'mptcp_make_after_break': 'no',
             'mptcp_no_join_dss_ack': 'no', 'mptcp_rto_max': 5, 'mptcp_retransmit_min': 1000, 'mptcp_subflow_max': 6,
             'mptcp_timeout': 3600, 'nagle_algorithm': 'yes', 'pkt_loss_ignore_burst': 0, 'pkt_loss_ignore_rate': 0,
             'proxy_buffer_high': 49152, 'proxy_buffer_low': 32768, 'proxy_max_segment': 'yes', 'proxy_options': 'yes',
             'push_flag': 'default', 'rate_pace': 'no', 'rate_pace_max_rate': 0, 'receive_window': 65535,
             'reset_on_timeout': 'yes', 'retransmit_threshold': 3, 'selective_acks': 'yes', 'selective_nack': 'no',
             'send_buffer': 131072, 'slow_start': 'no', 'syn_cookie_enable': 'yes', 'syn_cookie_white_list': 'no',
             'syn_retrans_to_base': 3000, 'tail_loss_probe': 'no', 'time_wait_recycle': 'yes', 'time_wait': '2000',
             'timestamps': 'yes', 'verified_accept': 'no', 'zero_window_timeout': 20000}
        )

    def test_get_tcp_profile_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['tcp-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TcpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_udp_profile_facts(self, *args):
        set_module_args(dict(
            gather_subset=['udp-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = UdpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_udp_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('udp_profiles', results)
        self.assertTrue(len(results['udp_profiles']) == 4)
        self.assertDictEqual(
            results['udp_profiles'][0],
            {'full_path': '/Common/udp', 'name': 'udp', 'parent': 'none', 'allow_no_payload': 'no',
             'buffer_max_bytes': 655350, 'buffer_max_packets': 0, 'datagram_load_balancing': 'no', 'idle_timeout': '60',
             'ip_df_mode': 'pmtu', 'ip_tos_to_client': '0', 'ip_ttl_mode': 'proxy', 'ip_ttl_v4': 255, 'ip_ttl_v6': 64,
             'link_qos_to_client': '0', 'no_checksum': 'no', 'proxy_mss': 'no'}
        )

    def test_get_udp_profile_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['udp-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = UdpProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_server_ssl_profiles_facts(self, *args):
        set_module_args(dict(
            gather_subset=['server-ssl-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ServerSslProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_serverssl_profiles.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('server_ssl_profiles', results)
        self.assertTrue(len(results['server_ssl_profiles']) == 10)
        self.assertDictEqual(
            results['server_ssl_profiles'][0],
            {'full_path': '/Common/apm-default-serverssl', 'name': 'apm-default-serverssl',
             'parent': '/Common/serverssl', 'unclean_shutdown': 'yes', 'strict_resume': 'no',
             'ssl_forward_proxy_enabled': 'no', 'ssl_forward_proxy_bypass': 'no', 'sni_default': 'no',
             'sni_require': 'no', 'ssl_c3d': 'no', 'session_mirroring': 'no', 'session_ticket': 'no',
             'mod_ssl_methods': 'no', 'allow_expired_crl': 'no', 'retain_certificate': 'yes', 'mode': 'yes',
             'bypass_on_client_cert_fail': 'no', 'bypass_on_handshake_alert': 'no', 'generic_alert': 'yes',
             'renegotiation': 'yes', 'proxy_ssl': 'no', 'proxy_ssl_passthrough': 'no', 'peer_cert_mode': 'require',
             'untrusted_cert_response_control': 'drop', 'ssl_sign_hash': 'any', 'secure_renegotiation': 'request',
             'renegotiate_size': 'indefinite', 'renegotiate_period': 'indefinite',
             'options': '{ dont-insert-empty-fragments no-tlsv1.3 no-dtlsv1.2 }', 'max_active_handshakes': 'indefinite',
             'key': 'none', 'handshake_timeout': '10', 'expire_cert_response_control': 'drop', 'cert': 'none',
             'chain': 'none', 'authentication_frequency': 'once', 'ciphers': 'DEFAULT', 'cipher_group': 'none',
             'cache_timeout': 3600, 'cache_size': 262144, 'ca_file': '/Common/ca-bundle.crt', 'c3d_cert_lifespan': 24,
             'alert_timeout': 'indefinite', 'authenticate_depth': 9,
             'c3d_cert_extension_includes': ['basic-constraints', 'extended-key-usage', 'key-usage',
                                             'subject-alternative-name']}
        )

    def test_get_server_ssl_profiles_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['server-ssl-profiles']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ServerSslProfilesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestSslKeyCertFactManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_ssl_cert_facts(self, *args):
        set_module_args(dict(
            gather_subset=['ssl-certs']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SslCertificatesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ssl_certs.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('ssl_certs', results)
        self.assertDictEqual(
            results['ssl_certs'][0],
            {'full_path': '/Common/ca-bundle.crt', 'name': 'ca-bundle.crt', 'key_type': 'rsa-public', 'key_size': 2048,
             'system_path': '/config/ssl/ssl.crt/ca-bundle.crt',
             'sha1_checksum': 'f881d0dceda4398b08d7369caad8729e94a868d2',
             'subject': 'CN=Starfield Services Root Certificate Authority,'
                        'OU=http://certificates.starfieldtech.com/repository/,O=Starfield Technologies, Inc.,'
                        'L=Scottsdale,ST=Arizona,C=US',
             'last_update_time': '2020-06-24T01:29:01Z',
             'issuer': 'CN=Starfield Services Root Certificate Authority,'
                       'OU=http://certificates.starfieldtech.com/repository/,O=Starfield Technologies, Inc.,'
                       'L=Scottsdale,ST=Arizona,C=US',
             'is_bundle': 'yes',
             'fingerprint': 'SHA256/B5:BD:2C:B7:9C:BD:19:07:29:8D:6B:DF:48:42:E5:16:'
                            'D8:C7:8F:A6:FC:96:D2:5F:71:AF:81:4E:16:CC:24:5E',
             'expiration_date': 'Dec 31 23:59:59 2029 GMT', 'expiration_timestamp': 1893455999,
             'create_time': '2020-06-24T01:29:01Z'}
        )

    def test_get_ssl_cert_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ssl-certs']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SslCertificatesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_ssl_key_facts(self, *args):
        set_module_args(dict(
            gather_subset=['ssl-keys']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SslKeysFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ssl_keys.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('ssl_keys', results)
        self.assertDictEqual(
            results['ssl_keys'][0],
            {'full_path': '/Common/default.key', 'name': 'default.key', 'key_type': 'rsa-private', 'key_size': 2048,
             'security_type': 'normal', 'system_path': '/config/ssl/ssl.key/default.key',
             'sha1_checksum': '4dd3a90a167a33fb54b8bd3433b46a239d16b6d9'}
        )
        self.assertDictEqual(
            results['ssl_keys'][1],
            {'full_path': '/Common/f5_api_com.key', 'name': 'f5_api_com.key', 'key_type': 'rsa-private',
             'key_size': 4096, 'security_type': 'password', 'sha1_checksum': 'af4aff9aaedee7ef6b6d549835bb2c106c2a3efc'}
        )

    def test_get_ssl_key_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ssl-keys']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SslKeysFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestSoftwareVolumesFactManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_software_volumes_facts(self, *args):
        set_module_args(dict(
            gather_subset=['software-volumes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SoftwareVolumesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_volumes.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('software_volumes', results)
        self.assertDictEqual(
            results['software_volumes'][0],
            {'full_path': 'HD1.1', 'name': 'HD1.1', 'active': 'yes', 'base_build': '0.0.1645', 'build': '0.0.1645',
             'product': 'BIG-IP', 'status': 'complete', 'version': '13.0.0', 'install_volume': 'HD1.1',
             'default_boot_location': 'yes'}
        )
        self.assertDictEqual(
            results['software_volumes'][1],
            {'full_path': 'HD1.2', 'name': 'HD1.2', 'active': 'no', 'base_build': '0.0.1645', 'build': '0.0.1645',
             'product': 'BIG-IP', 'status': 'complete', 'version': '13.0.0', 'install_volume': 'HD1.2'}
        )

    def test_get_software_volumes_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['software-volumes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SoftwareVolumesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_software_hotfix_facts(self, *args):
        set_module_args(dict(
            gather_subset=['software-hotfixes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SoftwareHotfixesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('list_hotfixes_local.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('software_hotfixes', results)
        self.assertTrue(len(results['software_hotfixes']) == 5)
        self.assertDictEqual(
            results['software_hotfixes'][0],
            {'name': '11.5.3-hf2', 'full_path': '11.5.3-hf2', 'build': '2.0.196',
             'checksum': '58d36d4c9bedd4592399ee6f7dc9e7fd', 'id': 'HF2', 'product': 'BIG-IP',
             'title': 'Hotfix Version 2.0.196', 'verified': 'yes', 'version': '11.5.3'}
        )
        self.assertDictEqual(
            results['software_hotfixes'][4],
            {'name': 'Hotfix-BIGIP-12.1.0.1.0.1447-HF1.iso', 'full_path': 'Hotfix-BIGIP-12.1.0.1.0.1447-HF1.iso',
             'build': '1.0.1447', 'checksum': 'c727a20957d5cbce287f99c0ba3fe83f', 'id': 'HF1', 'product': 'BIG-IP',
             'title': 'Hotfix Version 1.0.1447', 'verified': 'yes', 'version': '12.1.0'}
        )

    def test_get_software_hotfixes_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['software-hotfixes']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SoftwareHotfixesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_software_images_facts(self, *args):
        set_module_args(dict(
            gather_subset=['software-images']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SoftwareImagesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('list_images_local.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('software_images', results)
        self.assertTrue(len(results['software_images']) == 7)
        self.assertDictEqual(
            results['software_images'][0],
            {'name': '11.5.3', 'full_path': '11.5.3', 'build': '0.0.163', 'build_date': '2015-04-22T16:32:47',
             'checksum': '912c5862570bfdcd13bbc5f308e2e9b3', 'file_size': 1786, 'last_modified': '2017-04-18T14:09:02',
             'product': 'BIG-IP', 'verified': 'yes', 'version': '11.5.3'}
        )
        self.assertDictEqual(
            results['software_images'][6],
            {'name': 'BIGIP-12.1.2.0.0.249.iso', 'full_path': 'BIGIP-12.1.2.0.0.249.iso', 'build': '0.0.249',
             'build_date': '2016-11-30T16:04:00', 'checksum': '1b2bd1b0ae5e41e225b4ceea705f74e7', 'file_size': 2012,
             'last_modified': '2017-02-06T07:05:55', 'product': 'BIG-IP', 'verified': 'yes', 'version': '12.1.2'}
        )

    def test_get_software_images_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['software-images']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SoftwareImagesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestHaFactsManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_devices_facts(self, *args):
        set_module_args(dict(
            gather_subset=['devices']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = DevicesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_devices.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('devices', results)
        self.assertEqual(results['devices'][0]['full_path'], '/Common/bigip.example.com')
        self.assertEqual(results['devices'][0]['name'], 'bigip.example.com')
        self.assertTrue(len(results['devices'][0]['active_modules']) == 26)
        self.assertEqual(results['devices'][0]['base_mac_address'], 'fa:16:3e:7f:cf:b3')
        self.assertEqual(results['devices'][0]['build'], '0.0.12')
        self.assertEqual(results['devices'][0]['chassis_id'], '4225b5d3-0f0c-5068-c3dad20d67a4')
        self.assertEqual(results['devices'][0]['chassis_type'], 'individual')
        self.assertEqual(results['devices'][0]['edition'], 'Final')
        self.assertEqual(results['devices'][0]['failover_state'], 'active')
        self.assertEqual(results['devices'][0]['hostname'], 'bigip.example.com')
        self.assertEqual(results['devices'][0]['management_address'], '10.144.73.155')
        self.assertEqual(results['devices'][0]['marketing_name'], 'BIG-IP Virtual Edition')
        self.assertEqual(results['devices'][0]['multicast_address'], 'any6')
        self.assertTrue(len(results['devices'][0]['optional_modules']) == 36)
        self.assertEqual(results['devices'][0]['platform_id'], 'Z100')
        self.assertEqual(results['devices'][0]['product'], 'BIG-IP')
        self.assertEqual(results['devices'][0]['self'], 'yes')
        self.assertEqual(results['devices'][0]['software_version'], '16.0.0')
        self.assertEqual(results['devices'][0]['timezone'], 'UTC')

    def test_get_devices_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['devices']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = DevicesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_device_groups_facts(self, *args):
        set_module_args(dict(
            gather_subset=['device-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = DeviceGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_device_groups.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('device_groups', results)
        self.assertTrue(len(results['device_groups']) == 5)
        self.assertDictEqual(
            results['device_groups'][0],
            {'full_path': '/Common/datasync-device-bigip.example.com-dg',
             'name': 'datasync-device-bigip.example.com-dg', 'autosync_enabled': 'yes',
             'devices': ['/Common/bigip.example.com'], 'full_load_on_sync': 'yes',
             'incremental_config_sync_size_maximum': 1024, 'network_failover_enabled': 'no', 'type': 'sync-only',
             'asm_sync_enabled': 'no'}
        )

    def test_get_device_groups_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['device-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = DeviceGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_sync_status_facts(self, *args):
        set_module_args(dict(
            gather_subset=['sync-status']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SyncStatusFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_sys_sync_status.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('sync_status', results)
        self.assertDictEqual(
            results['sync_status'][0],
            {'color': 'green', 'details': ['Optional action: Add a device to the trust domain'], 'mode': 'standalone',
             'recommended_action': '', 'status': 'Standalone', 'summary': ''}
        )

    def test_get_sync_status_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['sync-status']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SyncStatusFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_tg_facts_with_stats(self, *args):
        set_module_args(dict(
            gather_subset=['traffic-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TrafficGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_tgs.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_tg_stats.json')),
            dict(code=200, contents={}),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(tm.client.get.call_count == 5)
        self.assertDictEqual(
            results['traffic_groups'][0],
            {'full_path': '/Common/asd', 'name': 'asd', 'auto_failback_enabled': 'no', 'auto_failback_time': 60,
             'ha_load_factor': 1, 'is_floating': 'yes', 'mac_masquerade_address': '00:00:00:00:00:02'}
        )
        self.assertDictEqual(
            results['traffic_groups'][1]['stats'],
            {'activeReason': '-', 'deviceName': '/Common/bigip.example.com', 'failoverState': 'active',
             'nextActive': 'false', 'previousActive': 'true', 'trafficGroup': '/Common/traffic-group-1'}
        )

    def test_get_tg_facts_stats_raises(self, *args):
        set_module_args(dict(
            gather_subset=['traffic-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TrafficGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_tgs.json')),
            dict(code=200, contents={}),
            dict(code=401, contents='access denied')
        ])
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(tm.client.get.call_count == 3)

    def test_get_tg_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['traffic-groups']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = TrafficGroupsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestSystemFactsManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_interfaces_facts(self, *args):
        set_module_args(dict(
            gather_subset=['interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = InterfacesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_interfaces.json')),
            dict(code=200, contents={})]
        )
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('interfaces', results)
        self.assertDictEqual(
            results['interfaces'][0],
            {'full_path': '1.1', 'name': '1.1', 'active_media_type': '10000T-FD', 'flow_control': 'tx-rx',
             'bundle': 'not-supported', 'bundle_speed': 'not-supported', 'enabled': 'yes', 'if_index': 48,
             'mac_address': 'fa:16:3e:0f:ec:f5', 'media_sfp': 'auto', 'lldp_admin': 'txonly', 'mtu': 9198,
             'prefer_port': 'sfp', 'sflow_poll_interval': 0, 'sflow_poll_interval_global': 'yes',
             'stp_auto_edge_port': 'yes', 'stp_enabled': 'yes', 'stp_link_type': 'auto'}
        )

    def test_get_interfaces_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = InterfacesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_license_facts(self, *args):
        set_module_args(dict(
            gather_subset=['license']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = LicenseFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_sys_license.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('license', results)
        self.assertTrue(len(results['license']['active_modules']) == 5)
        self.assertEqual(results['license']['license_start_date'], '2022/03/27')
        self.assertEqual(results['license']['license_end_date'], '2023/04/06')
        self.assertEqual(results['license']['licensed_on_date'], '2023/01/16')
        self.assertEqual(results['license']['licensed_version'], '16.0.0')
        self.assertEqual(results['license']['max_permitted_version'], '18.*.*')
        self.assertEqual(results['license']['min_permitted_version'], '5.*.*')
        self.assertEqual(results['license']['platform_id'], 'Z100')
        self.assertEqual(results['license']['registration_key'], 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXXXXX')
        self.assertEqual(results['license']['service_check_date'], '2023/03/07')

    def test_get_license_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['license']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = RemoteSyslogFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_remote_syslog_facts(self, *args):
        set_module_args(dict(
            gather_subset=['remote-syslog']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = RemoteSyslogFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_remote_syslog.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('remote_syslog', results)
        self.assertDictEqual(
            results['remote_syslog'], {'servers': [{'name': '/Common/remotesyslog1', 'remote_port': 514,
                                                    'local_ip': '10.10.10.11', 'remote_host': '1.1.1.1'}]}
        )

    def test_get_remote_syslog_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['remote-syslog']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = RemoteSyslogFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_ucs_facts(self, *args):
        set_module_args(dict(
            gather_subset=['ucs']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = UCSFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ucs_files.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('ucs_files', results)
        self.assertDictEqual(
            results['ucs_files'][0],
            {'file_name': 'foo.ucs', 'encrypted': 'no', 'file_size': '56214358',
             'file_created_date': '2022-11-20T20:23:05Z'}
        )

    def test_get_ucs_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['ucs']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = UCSFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_users_facts(self, *args):
        set_module_args(dict(
            gather_subset=['users']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = UsersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_users.json')))
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('users', results)
        self.assertDictEqual(
            results['users'][0],
            {'full_path': 'admin', 'name': 'admin', 'description': 'Admin User',
             'partition_access': [{'name': 'all-partitions', 'role': 'admin'}]}
        )
        self.assertDictEqual(
            results['users'][1],
            {'full_path': 'foobar', 'name': 'foobar', 'description': 'foobar',
             'partition_access': [{'name': 'all-partitions', 'role': 'manager'}], 'shell': 'tmsh'}
        )

    def test_get_users_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['users']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = UsersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_partitions_facts(self, *args):
        set_module_args(dict(
            gather_subset=['partitions']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = PartitionFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_partitions.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('partitions', results)
        self.assertDictEqual(
            results['partitions'][0],
            {'name': 'Common', 'full_path': 'Common', 'description': 'Updated by AS3 at Wed, 12 Oct 2022 00:06:21 GMT',
             'default_route_domain': 0}
        )

    def test_get_partitions_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['partitions']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = PartitionFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_system_db_facts(self, *args):
        set_module_args(dict(
            gather_subset=['system-db']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SystemDbFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_sys_dbs.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('system_db', results)
        self.assertTrue(len(results['system_db']) == 2400)
        self.assertDictEqual(
            results['system_db'][0],
            {'name': 'acceleration.log.color', 'full_path': 'acceleration.log.color', 'default': 'no_color',
             'scf_config': 'true', 'value': 'no_color', 'value_range': 'color_level color_line no_color'}
        )

    def test_get_system_db_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['system-db']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SystemDbFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])

    def test_get_sys_provision_facts(self, *args):
        set_module_args(dict(
            gather_subset=['provision-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ProvisionInfoFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_sys_provision.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('provision_info', results)
        self.assertTrue(len(results['provision_info']) == 15)
        self.assertDictEqual(
            results['provision_info'][0],
            {'full_path': 'afm', 'name': 'afm', 'cpu_ratio': 0, 'disk_ratio': 0, 'memory_ratio': 0, 'level': 'nominal'}
        )

    def test_get_sys_provision_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['provision-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = ProvisionInfoFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestSystemInfoFactsManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_system_info_facts(self, *args):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = SystemInfoFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_hardware_info.json')),
            dict(code=200, contents=load_fixture('load_sys_clock.json')),
            dict(code=200, contents=load_fixture('load_sys_version.json'))
        ])
        tm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_sys_uptime_info.json')),
            dict(code=200, contents=load_fixture('load_sys_file_version_info.json'))
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(tm.client.get.call_count == 3)
        self.assertTrue(tm.client.post.call_count == 2)
        self.assertIn('system_info', results)
        self.assertDictEqual(
            results['system_info'],
            {'base_mac_address': 'fa:16:3e:7f:cf:b3', 'marketing_name': 'BIG-IP Virtual Edition',
             'time': {'day': 8, 'hour': 18, 'minute': 32, 'month': 3, 'second': 59, 'year': 2023},
             'hardware_information': [{'model': 'Virtual disk', 'type': 'physical-disk',
                                       'versions': [{'version': 'VMware-sda', 'name': 'SerialNumber'},
                                                    {'version': '175.00G', 'name': 'Size'},
                                                    {'version': '2.0', 'name': 'Firmware Version'},
                                                    {'version': 'HDD', 'name': 'Media Type'}], 'name': 'HD1'},
                                      {'model': 'Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz', 'type': 'base-board',
                                       'versions': [{'version': '35840 KB', 'name': 'cache size'},
                                                    {'version': '4  (physical:4)', 'name': 'cores'},
                                                    {'version': '2593.993', 'name': 'cpu MHz'},
                                                    {'version': '4', 'name': 'cpu sockets'},
                                                    {'version': '0', 'name': 'cpu stepping'}], 'name': 'cpus'}],
             'package_edition': 'Final', 'package_version': 'Build 0.0.12 - Tue Jun 23 18:31:26 PDT 2020',
             'product_code': 'BIG-IP', 'product_build': '0.0.12', 'product_built': 200623183126,
             'product_build_date': 'Tue Jun 23 18:31:26 PDT 2020', 'product_changelist': 3348116,
             'product_jobid': 1207889, 'product_version': '16.0.0', 'uptime': 35193005,
             'chassis_serial': '4225b5d3-0f0c-5068-c3dad20d67a4', 'platform': 'Z100'}
        )

    def test_get_system_info_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        tm = SystemInfoFactManager(module=module, client=MagicMock())

        tm.client.post = Mock(side_effect=[
            dict(code=401, contents='access denied'),
            dict(code=200, contents={}),
            dict(code=200, contents=dict(commandResult='No such file or directory')),
            dict(code=401, contents='access denied'),
            dict(code=200, contents={}),

        ])
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))

        with self.assertRaises(F5ModuleError) as err:
            tm.read_version_file_info_from_device()
        self.assertIn('access denied', err.exception.args[0])

        self.assertIsNone(tm.read_version_file_info_from_device())
        self.assertIsNone(tm.read_version_file_info_from_device())

        with self.assertRaises(F5ModuleError) as err2:
            tm.read_uptime_info_from_device()
        self.assertIn('access denied', err2.exception.args[0])

        self.assertIsNone(tm.read_uptime_info_from_device())

        with self.assertRaises(F5ModuleError) as err3:
            tm.read_hardware_info_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            tm.read_clock_info_from_device()
        self.assertIn('access denied', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            tm.read_version_info_from_device()
        self.assertIn('access denied', err5.exception.args[0])

        self.assertTrue(tm.client.get.call_count == 3)
        self.assertTrue(tm.client.post.call_count == 5)


class TestVirtualFactsManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['ltm']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_virtual_server_facts(self, *args):
        set_module_args(dict(
            gather_subset=['virtual-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VirtualServersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_virtual_server_facts.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_ltm_virtual_server_stats.json')),
            dict(code=200, contents=load_fixture('load_fasthttp_profiles.json')),
            dict(code=200, contents=load_fixture('load_fastl4_profiles.json')),
            dict(code=200, contents=load_fixture('load_diameter_profiles.json')),
            dict(code=200, contents=load_fixture('load_sip_profiles.json')),
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('virtual_servers', results)
        self.assertTrue(tm.client.get.call_count == 7)
        self.assertTrue(results['virtual_servers'][0]['destination'] == '/Common/192.168.1.1:443')
        self.assertTrue(results['virtual_servers'][0]['type'] == 'standard')
        self.assertListEqual(
            results['virtual_servers'][0]['profiles'],
            [{'name': 'clientssl', 'context': 'client-side', 'full_path': '/Common/clientssl'},
             {'name': 'http', 'context': 'all', 'full_path': '/Common/http'},
             {'name': 'tcp', 'context': 'all', 'full_path': '/Common/tcp'}]
        )

    def test_get_virtual_server_facts_no_stats(self, *args):
        set_module_args(dict(
            gather_subset=['virtual-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VirtualServersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_virtual_server_facts.json')),
            dict(code=200, contents={}),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('load_fasthttp_profiles.json')),
            dict(code=200, contents=load_fixture('load_fastl4_profiles.json')),
            dict(code=200, contents=load_fixture('load_diameter_profiles.json')),
            dict(code=200, contents=load_fixture('load_sip_profiles.json')),
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('virtual_servers', results)
        self.assertTrue(tm.client.get.call_count == 7)
        self.assertTrue(results['virtual_servers'][0]['destination'] == '/Common/192.168.1.1:443')
        self.assertTrue(results['virtual_servers'][0]['type'] == 'standard')
        self.assertListEqual(
            results['virtual_servers'][0]['profiles'],
            [{'name': 'clientssl', 'context': 'client-side', 'full_path': '/Common/clientssl'},
             {'name': 'http', 'context': 'all', 'full_path': '/Common/http'},
             {'name': 'tcp', 'context': 'all', 'full_path': '/Common/tcp'}]
        )

    @patch.object(VirtualServersParameters, '_read_current_fasthttp_profiles_from_device', new_callable=Mock())
    @patch.object(VirtualServersParameters, '_read_current_fastl4_profiles_from_device', new_callable=Mock())
    @patch.object(VirtualServersParameters, '_read_diameter_profiles_from_device', new_callable=Mock())
    @patch.object(VirtualServersParameters, '_read_sip_profiles_from_device', new_callable=Mock())
    def test_get_virtual_servers_facts(self, f1, f2, f3, f4):
        set_module_args(dict(
            gather_subset=['virtual-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        f4.return_value = fake_read_profiles(load_fixture('load_fasthttp_profiles.json'))
        f3.return_value = fake_read_profiles(load_fixture('load_fastl4_profiles.json'))
        f2.return_value = fake_read_profiles(load_fixture('load_diameter_profiles.json'))
        f1.return_value = fake_read_profiles(load_fixture('load_sip_profiles.json'))
        to_return = parseStats(load_fixture('load_ltm_virtual_server_stats.json'))

        tm = VirtualServersFactManager(module=module, client=MagicMock())
        tm.read_stats_from_device = Mock(return_value=to_return.get('stats'))
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_virtual_servers_facts.json')),
            dict(code=200, contents={})
        ])

        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()
        self.assertTrue(results['queried'])
        self.assertTrue(len(results['virtual_servers']) == 10)
        self.assertTrue(results['virtual_servers'][0]['name'] == 'fake_dhcp')
        self.assertTrue(results['virtual_servers'][0]['type'] == 'dhcp')
        self.assertTrue(results['virtual_servers'][-1]['name'] == 'fake_stateless')
        self.assertTrue(results['virtual_servers'][-1]['type'] == 'stateless')

    def test_get_virtual_server_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['virtual-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VirtualServersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=404, contents='not found'))

        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])

    def test_get_virtual_server_facts_stats_raises(self, *args):
        set_module_args(dict(
            gather_subset=['virtual-servers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VirtualServersFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_virtual_server_facts.json')),
            dict(code=200, contents={}),
            dict(code=404, contents='not found')
        ])

        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])
        self.assertTrue(tm.client.get.call_count == 3)

    def test_virtual_server_params_read_methods_failures(self):
        fv = VirtualServersParameters(client=Mock(), params=dict())
        fv.client.get = Mock(return_value=dict(code=404, contents='not found'))

        with self.assertRaises(F5ModuleError) as err1:
            fv._read_diameter_profiles_from_device()
        self.assertIn('not found', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            fv._read_sip_profiles_from_device()
        self.assertIn('not found', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            fv._read_current_fastl4_profiles_from_device()
        self.assertIn('not found', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            fv._read_current_fasthttp_profiles_from_device()
        self.assertIn('not found', err4.exception.args[0])

    def test_get_virtual_address_facts(self, *args):
        set_module_args(dict(
            gather_subset=['virtual-addresses']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VirtualAddressesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_ltm_virtual_address_collection_1.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('virtual_addresses', results)
        self.assertDictEqual(
            results['virtual_addresses'][0],
            {'full_path': '/Common/2.3.4.5', 'name': '2.3.4.5', 'address': '2.3.4.5', 'arp_enabled': 'yes',
             'auto_delete_enabled': 'yes', 'connection_limit': 0, 'enabled': 'yes', 'icmp_echo': 'yes',
             'floating': 'yes', 'netmask': '255.255.255.255', 'route_advertisement': 'no',
             'traffic_group': '/Common/traffic-group-1', 'spanning': 'no', 'inherited_traffic_group': 'no'}
        )

    def test_get_virtual_address_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['virtual-addresses']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VirtualAddressesFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestVcmpFactsManagers(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.modules_provisioned')
        self.m1 = self.p1.start()
        self.m1.return_value = ['vcmp']
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_vcmp_guest_facts(self, *args):
        set_module_args(dict(
            gather_subset=['vcmp-guests']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VcmpGuestsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_vcmp_guests.json')),
            dict(code=200, contents={})
        ])
        mm.get_manager = Mock(return_value=tm)

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertIn('vcmp_guests', results)
        self.assertDictEqual(
            results['vcmp_guests'][0],
            {'name': 'vcmp02_s1m1c4', 'full_path': 'vcmp02_s1m1c4', 'allowed_slots': [1, 2, 3, 4, 5, 6, 7, 8],
             'assigned_slots': [2], 'boot_priority': 65535, 'cores_per_slot': 2,
             'hostname': 'localhost.localdomain',
             'initial_image': 'BIGIP-tmos-tier2-13.1.0.0.0.931.iso', 'mgmt_route': '10.144.3.254',
             'mgmt_address': '10.144.3.97/24', 'mgmt_network': 'bridged', 'vlans': ['/Common/tim', '/Common/vt'],
             'min_number_of_slots': 1, 'number_of_slots': 1, 'ssl_mode': 'shared', 'state': 'deployed',
             'virtual_disk': 'vcmp02_s1m1c4.img'}
        )

    def test_get_vcmp_guest_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['vcmp-guests']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        tm = VcmpGuestsFactManager(module=module, client=MagicMock())
        tm.client.get = Mock(return_value=dict(code=401, contents='access denied'))
        mm.get_manager = Mock(return_value=tm)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])


class TestMainFunction(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.mock_module_helper.stop()

    @patch.object(bigip_device_info, 'Connection')
    @patch.object(bigip_device_info.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            gather_subset=['all']
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_device_info.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_device_info, 'Connection')
    @patch.object(bigip_device_info.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            gather_subset=['all']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_device_info.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
