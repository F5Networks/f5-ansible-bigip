# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5_bigip.plugins.modules import bigip_security_log_profile
from ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_log_profile import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5_bigip.tests.compat import unittest
from ansible_collections.f5networks.f5_bigip.tests.compat.mock import (
    Mock, patch, MagicMock
)
from ansible_collections.f5networks.f5_bigip.tests.modules.utils import (
    set_module_args, fail_json, exit_json, AnsibleExitJson, AnsibleFailJson
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
            name='test_log_profile',
            description='this is a log profile test',
            auto_discovery='local-db-publisher',
            dos_protection=dict(
                application='local-db-publisher',
                network='local-db-publisher',
                dns='local-db-publisher',
                sip='local-db-publisher'
            ),
            protocol_inspection=dict(
                log_packet=True,
                publisher='local-db-publisher'
            ),
            packet_filter=dict(
                rate=300,
                publisher='local-db-publisher'
            ),
            classification=dict(
                log_matches=True,
                publisher='local-db-publisher'
            ),
            bot_defense=dict(
                publisher='local-db-publisher',
                send_remote_challenge_failure_messages='no',
                filter=dict(
                    log_alarm=True,
                    log_block=False,
                    log_browser=True,
                    log_browser_verification_action=True,
                    log_captcha=False,
                    log_challenge_failure_request=True,
                    log_device_id_collection_request=False,
                    log_honeypot_page=False,
                    log_mobile_application=False,
                    log_none=False,
                    log_rate_limit=True,
                    log_redirect_to_pool=False,
                    log_suspicious_browser=True,
                    log_tcp_reset=False,
                    log_trusted_bot=True,
                    log_unknown=True,
                    log_untrusted_bot=True
                )
            )
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.description, 'this is a log profile test')
        self.assertEqual(p.auto_discovery, '/Common/local-db-publisher')
        self.assertEqual(p.dos_app_publisher, '/Common/local-db-publisher')
        self.assertEqual(p.dos_dns_pub, '/Common/local-db-publisher')
        self.assertEqual(p.dos_net_pub, '/Common/local-db-publisher')
        self.assertEqual(p.dos_sip_pub, '/Common/local-db-publisher')
        self.assertEqual(p.proto_inspect_log, 'enabled')
        self.assertEqual(p.proto_inspect_pub, '/Common/local-db-publisher')
        self.assertEqual(p.packet_filter_rate, 300)
        self.assertEqual(p.packet_filter_pub, '/Common/local-db-publisher')
        self.assertEqual(p.classification_log, 'enabled')
        self.assertEqual(p.classification_pub, '/Common/local-db-publisher')
        self.assertEqual(p.bot_publisher, '/Common/local-db-publisher')
        self.assertEqual(p.bot_remote_chall_fail_msg, 'disabled')
        self.assertEqual(p.bot_log_alarm, 'enabled')
        self.assertEqual(p.bot_log_block, 'disabled')
        self.assertEqual(p.bot_log_browser, 'enabled')
        self.assertEqual(p.bot_log_browser_verify, 'enabled')
        self.assertEqual(p.bot_log_captcha, 'disabled')
        self.assertEqual(p.bot_log_challenge_failure, 'enabled')
        self.assertEqual(p.bot_log_deviceid_coll_req, 'disabled')
        self.assertEqual(p.bot_log_honey_pot, 'disabled')
        self.assertEqual(p.bot_log_mobile_app, 'disabled')
        self.assertEqual(p.bot_log_none, 'disabled')
        self.assertEqual(p.bot_log_rate_limit, 'enabled')
        self.assertEqual(p.bot_log_redirect_to_pool, 'disabled')
        self.assertEqual(p.bot_log_suspect_browser, 'enabled')
        self.assertEqual(p.bot_log_tcp_reset, 'disabled')
        self.assertEqual(p.bot_log_trusted_bot, 'enabled')
        self.assertEqual(p.bot_log_unknown, 'enabled')
        self.assertEqual(p.bot_log_untrusted_bot, 'enabled')

    def test_invalid_rate_raises(self):
        args = dict(packet_filter=dict(rate=10000))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.packet_filter_rate()

        self.assertIn('rate value must be between 1 and 1000 messages per second', err.exception.args[0])

    def test_invalid_bot_publisher_raises(self):
        args = dict(bot_defense=dict(publisher=''))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.bot_publisher()

        self.assertIn('Publisher cannot be set to '' when configuring bot defense logging', err.exception.args[0])

    def test_module_parameters_none(self):
        args = dict(name='test_log_profile')

        p = ModuleParameters(params=args)

        self.assertIsNone(p.description)
        self.assertIsNone(p.auto_discovery)
        self.assertIsNone(p.dos_app_publisher)
        self.assertIsNone(p.dos_dns_pub)
        self.assertIsNone(p.dos_net_pub)
        self.assertIsNone(p.dos_sip_pub)
        self.assertIsNone(p.proto_inspect_log)
        self.assertIsNone(p.proto_inspect_pub)
        self.assertIsNone(p.packet_filter_rate)
        self.assertIsNone(p.packet_filter_pub)
        self.assertIsNone(p.classification_log)
        self.assertIsNone(p.classification_pub)
        self.assertIsNone(p.bot_publisher)
        self.assertIsNone(p.bot_remote_chall_fail_msg)
        self.assertIsNone(p.bot_log_alarm)
        self.assertIsNone(p.bot_log_block)
        self.assertIsNone(p.bot_log_browser)
        self.assertIsNone(p.bot_log_browser_verify)
        self.assertIsNone(p.bot_log_captcha)
        self.assertIsNone(p.bot_log_challenge_failure)
        self.assertIsNone(p.bot_log_deviceid_coll_req)
        self.assertIsNone(p.bot_log_honey_pot)
        self.assertIsNone(p.bot_log_mobile_app)
        self.assertIsNone(p.bot_log_none)
        self.assertIsNone(p.bot_log_rate_limit)
        self.assertIsNone(p.bot_log_redirect_to_pool)
        self.assertIsNone(p.bot_log_suspect_browser)
        self.assertIsNone(p.bot_log_tcp_reset)
        self.assertIsNone(p.bot_log_trusted_bot)
        self.assertIsNone(p.bot_log_unknown)
        self.assertIsNone(p.bot_log_untrusted_bot)

    def test_api_parameters(self):
        args = load_fixture('load_log_security_profile.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.description, 'this is a log profile test')
        self.assertEqual(p.auto_discovery, '/Common/local-db-publisher')
        self.assertEqual(p.dos_app_publisher, '/Common/local-db-publisher')
        self.assertEqual(p.dos_dns_pub, '/Common/local-db-publisher')
        self.assertEqual(p.dos_net_pub, '/Common/local-db-publisher')
        self.assertEqual(p.dos_sip_pub, '/Common/local-db-publisher')
        self.assertEqual(p.proto_inspect_log, 'enabled')
        self.assertEqual(p.proto_inspect_pub, '/Common/local-db-publisher')
        self.assertEqual(p.packet_filter_rate, 300)
        self.assertEqual(p.packet_filter_pub, '/Common/local-db-publisher')
        self.assertEqual(p.classification_log, 'enabled')
        self.assertEqual(p.classification_pub, '/Common/local-db-publisher')
        self.assertEqual(p.bot_publisher, '/Common/local-db-publisher')
        self.assertEqual(p.bot_remote_chall_fail_msg, 'disabled')
        self.assertEqual(p.bot_log_alarm, 'enabled')
        self.assertEqual(p.bot_log_block, 'disabled')
        self.assertEqual(p.bot_log_browser, 'enabled')
        self.assertEqual(p.bot_log_browser_verify, 'enabled')
        self.assertEqual(p.bot_log_captcha, 'disabled')
        self.assertEqual(p.bot_log_challenge_failure, 'enabled')
        self.assertEqual(p.bot_log_deviceid_coll_req, 'disabled')
        self.assertEqual(p.bot_log_honey_pot, 'disabled')
        self.assertEqual(p.bot_log_mobile_app, 'disabled')
        self.assertEqual(p.bot_log_none, 'disabled')
        self.assertEqual(p.bot_log_rate_limit, 'enabled')
        self.assertEqual(p.bot_log_redirect_to_pool, 'disabled')
        self.assertEqual(p.bot_log_suspect_browser, 'enabled')
        self.assertEqual(p.bot_log_tcp_reset, 'disabled')
        self.assertEqual(p.bot_log_trusted_bot, 'enabled')
        self.assertEqual(p.bot_log_unknown, 'enabled')
        self.assertEqual(p.bot_log_untrusted_bot, 'enabled')

    def test_api_parameters_none(self):
        p = ApiParameters(params=dict())

        self.assertFalse(p.bot_defense_exists)
        self.assertIsNone(p.description)
        self.assertIsNone(p.auto_discovery)
        self.assertIsNone(p.dos_app_publisher)
        self.assertIsNone(p.dos_dns_pub)
        self.assertIsNone(p.dos_net_pub)
        self.assertIsNone(p.dos_sip_pub)
        self.assertIsNone(p.proto_inspect_log)
        self.assertIsNone(p.proto_inspect_pub)
        self.assertIsNone(p.packet_filter_rate)
        self.assertIsNone(p.packet_filter_pub)
        self.assertIsNone(p.classification_log)
        self.assertIsNone(p.classification_pub)
        self.assertIsNone(p.bot_publisher)
        self.assertIsNone(p.bot_remote_chall_fail_msg)
        self.assertIsNone(p.bot_log_alarm)
        self.assertIsNone(p.bot_log_block)
        self.assertIsNone(p.bot_log_browser)
        self.assertIsNone(p.bot_log_browser_verify)
        self.assertIsNone(p.bot_log_captcha)
        self.assertIsNone(p.bot_log_challenge_failure)
        self.assertIsNone(p.bot_log_deviceid_coll_req)
        self.assertIsNone(p.bot_log_honey_pot)
        self.assertIsNone(p.bot_log_mobile_app)
        self.assertIsNone(p.bot_log_none)
        self.assertIsNone(p.bot_log_rate_limit)
        self.assertIsNone(p.bot_log_redirect_to_pool)
        self.assertIsNone(p.bot_log_suspect_browser)
        self.assertIsNone(p.bot_log_tcp_reset)
        self.assertIsNone(p.bot_log_trusted_bot)
        self.assertIsNone(p.bot_log_unknown)
        self.assertIsNone(p.bot_log_untrusted_bot)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_log_profile.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True
        self.p2 = patch('ansible_collections.f5networks.f5_bigip.plugins.modules.bigip_security_log_profile.F5Client')
        self.m2 = self.p2.start()
        self.m2.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_log_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
            auto_discovery='local-db-publisher',
            dos_protection=dict(
                application='local-db-publisher',
                network='local-db-publisher',
                dns='local-db-publisher',
                sip='local-db-publisher'
            ),
            protocol_inspection=dict(
                log_packet=True,
                publisher='local-db-publisher'
            ),
            packet_filter=dict(
                rate=300,
                publisher='local-db-publisher'
            ),
            classification=dict(
                log_matches=True,
                publisher='local-db-publisher'
            ),
            bot_defense=dict(
                publisher='local-db-publisher',
                send_remote_challenge_failure_messages='no',
                filter=dict(
                    log_alarm=True,
                    log_block=False,
                    log_browser=True,
                    log_browser_verification_action=True,
                    log_captcha=False,
                    log_challenge_failure_request=True,
                    log_device_id_collection_request=False,
                    log_honeypot_page=False,
                    log_mobile_application=False,
                    log_none=False,
                    log_rate_limit=True,
                    log_redirect_to_pool=False,
                    log_suspicious_browser=True,
                    log_tcp_reset=False,
                    log_trusted_bot=True,
                    log_unknown=True,
                    log_untrusted_bot=True
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {
            'publisher': '/Common/local-db-publisher', 'send_remote_challenge_failure_messages': 'disabled',
            'filter': {'log_alarm': 'enabled', 'log_block': 'disabled', 'log_browser': 'enabled',
                       'log_browser_verification_action': 'enabled', 'log_captcha': 'disabled',
                       'log_challenge_failure_request': 'enabled', 'log_device_id_collection_request':
                           'disabled', 'log_honeypot_page': 'disabled', 'log_mobile_application': 'disabled',
                       'log_none': 'disabled', 'log_rate_limit': 'enabled', 'log_redirect_to_pool': 'disabled',
                       'log_suspicious_browser': 'enabled', 'log_tcp_reset': 'disabled', 'log_trusted_bot': 'enabled',
                       'log_unknown': 'enabled', 'log_untrusted_bot': 'enabled'}
        }
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(results['auto_discovery'], '/Common/local-db-publisher')
        self.assertDictEqual(results['bot_defense'], expected)
        self.assertEqual(results['description'], 'this is a log profile test')
        self.assertDictEqual(
            results['classification'], {'log_matches': 'enabled', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(
            results['dos_protection'], {'application': '/Common/local-db-publisher',
                                        'network': '/Common/local-db-publisher',
                                        'dns': '/Common/local-db-publisher', 'sip': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(results['packet_filter'], {'rate': 300, 'publisher': '/Common/local-db-publisher'})
        self.assertDictEqual(
            results['protocol_inspection'], {'log_packet': 'enabled', 'publisher': '/Common/local-db-publisher'}
        )

    def test_create_log_security_profile_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
            auto_discovery='local-db-publisher',
            dos_protection=dict(
                application='local-db-publisher',
                network='local-db-publisher',
                dns='local-db-publisher',
                sip='local-db-publisher'
            ),
            protocol_inspection=dict(
                log_packet=True,
                publisher='local-db-publisher'
            ),
            packet_filter=dict(
                rate=300,
                publisher='local-db-publisher'
            ),
            classification=dict(
                log_matches=True,
                publisher='local-db-publisher'
            ),
            bot_defense=dict(
                publisher='local-db-publisher',
                send_remote_challenge_failure_messages='no',
                filter=dict(
                    log_alarm=True,
                    log_block=False,
                    log_browser=True,
                    log_browser_verification_action=True,
                    log_captcha=False,
                    log_challenge_failure_request=True,
                    log_device_id_collection_request=False,
                    log_honeypot_page=False,
                    log_mobile_application=False,
                    log_none=False,
                    log_rate_limit=True,
                    log_redirect_to_pool=False,
                    log_suspicious_browser=True,
                    log_tcp_reset=False,
                    log_trusted_bot=True,
                    log_unknown=True,
                    log_untrusted_bot=True
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_log_security_profile.json')))

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_create_log_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(name='test_log_profile'))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_update_log_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes',
                filter=dict(
                    log_alarm=False,
                    log_block=True
                )
            ),
            packet_filter=dict(
                rate=100
            ),
            protocol_inspection=dict(
                log_packet=False,
                publisher=''
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_log_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(
            results['bot_defense'],
            {'send_remote_challenge_failure_messages': 'enabled',
             'filter': {'log_alarm': 'disabled', 'log_block': 'enabled'}}
        )
        self.assertDictEqual(results['packet_filter'], {'rate': 100})
        self.assertDictEqual(results['protocol_inspection'], {'log_packet': 'disabled', 'publisher': ''})

    def test_update_log_security_profile_no_change(self, *args):
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes',
                filter=dict(
                    log_alarm=False,
                    log_block=True
                )
            ),
            packet_filter=dict(
                rate=100
            ),
            protocol_inspection=dict(
                log_packet=False,
                publisher=''
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('load_log_security_profile_changed.json')
        ))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_log_security_profile_single_option(self, *args):
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes'
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected_call_args = {
            'sendRemoteChallengeFailureMessages': 'enabled', 'name': 'test_log_profile', 'partition': 'Common',
            'localPublisher': '/Common/local-db-publisher',
            'filter': {'logAlarm': 'enabled', 'logBlock': 'disabled', 'logBrowser': 'enabled',
                       'logBrowserVerificationAction': 'enabled', 'logCaptcha': 'disabled',
                       'logChallengeFailureRequest': 'enabled', 'logDeviceIdCollectionRequest': 'disabled',
                       'logHoneyPotPage': 'disabled', 'logMobileApplication': 'disabled', 'logNone': 'disabled',
                       'logRateLimit': 'enabled', 'logRedirectToPool': 'disabled', 'logSuspiciousBrowser': 'enabled',
                       'logTcpReset': 'disabled', 'logTrustedBot': 'enabled', 'logUnknown': 'enabled',
                       'logUntrustedBot': 'enabled'}
        }

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_log_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['bot_defense'], {'send_remote_challenge_failure_messages': 'enabled'})
        self.assertDictEqual(mm.client.patch.call_args_list[0][1]['data']['botDefense'][0], expected_call_args)

    def test_update_log_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes',
                filter=dict(
                    log_alarm=False,
                    log_block=True
                )
            )
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_log_security_profile.json')))
        mm.client.patch = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.patch.called)

    def test_delete_log_security_profile(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_log_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, True])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    def test_delete_log_security_profile_error_response(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            state='absent'
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value=dict(code=401, contents={'access denied'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('access denied', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    @patch.object(bigip_security_log_profile, 'Connection')
    @patch.object(bigip_security_log_profile.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            bigip_security_log_profile.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(bigip_security_log_profile, 'Connection')
    @patch.object(bigip_security_log_profile.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            bigip_security_log_profile.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())
