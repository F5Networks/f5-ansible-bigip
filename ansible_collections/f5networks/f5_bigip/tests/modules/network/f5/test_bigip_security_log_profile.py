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

    def test_nat_partial_parameters(self):
        args = dict(
            nat=dict(
                start_outbound_session=dict(include_dest_addr_port='no'),
                end_outbound_session=dict(include_dest_addr_port='no')
            )
        )

        p = ModuleParameters(params=args)

        self.assertListEqual(p.nat_start_out_incl_dst_addr_port, [])
        self.assertListEqual(p.nat_end_out_incl_dst_addr_port, [])

        args = dict(nat=dict(publisher='foobar'))

        p = ModuleParameters(params=args)

        self.assertIsNone(p.nat_start_out_storage_format_type)
        self.assertIsNone(p.nat_start_out_storage_format_delimiter)
        self.assertIsNone(p.nat_start_out_storage_format_fields)
        self.assertIsNone(p.nat_start_out_storage_format_user_string)

        self.assertIsNone(p.nat_end_out_storage_format_type)
        self.assertIsNone(p.nat_end_out_storage_format_delimiter)
        self.assertIsNone(p.nat_end_out_storage_format_fields)
        self.assertIsNone(p.nat_end_out_storage_format_user_string)

        self.assertIsNone(p.nat_start_in_storage_format_type)
        self.assertIsNone(p.nat_start_in_storage_format_delimiter)
        self.assertIsNone(p.nat_start_in_storage_format_fields)
        self.assertIsNone(p.nat_start_in_storage_format_user_string)

        self.assertIsNone(p.nat_end_in_storage_format_type)
        self.assertIsNone(p.nat_end_in_storage_format_delimiter)
        self.assertIsNone(p.nat_end_in_storage_format_fields)
        self.assertIsNone(p.nat_end_in_storage_format_user_string)

        self.assertIsNone(p.nat_quota_exceeded_storage_format_type)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_delimiter)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_fields)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_user_string)

        self.assertIsNone(p.nat_errors_storage_format_type)
        self.assertIsNone(p.nat_errors_storage_format_delimiter)
        self.assertIsNone(p.nat_errors_storage_format_fields)
        self.assertIsNone(p.nat_errors_storage_format_user_string)

    def test_format_type_none(self):
        args = dict(dns_security=dict(storage_format=dict(fields=['action'], user_string='foo', type='none')))

        p = ModuleParameters(params=args)

        self.assertIsNone(p.dns_storage_format_fields)
        self.assertIsNone(p.dns_storage_format_user_string)
        self.assertEqual(p.dns_storage_format_type, 'none')

        args = dict(sip_security=dict(storage_format=dict(fields=['action'], user_string='foo', type='none')))

        p = ModuleParameters(params=args)

        self.assertIsNone(p.sip_storage_format_fields)
        self.assertIsNone(p.sip_storage_format_user_string)
        self.assertEqual(p.sip_storage_format_type, 'none')

        args = dict(network_security=dict(storage_format=dict(fields=['action'], user_string='foo', type='none')))

        p = ModuleParameters(params=args)

        self.assertIsNone(p.net_storage_format_fields)
        self.assertIsNone(p.net_storage_format_user_string)
        self.assertEqual(p.net_storage_format_type, 'none')

        args = dict(nat=dict(
            start_outbound_session=dict(storage_format=dict(fields=['event_name'], user_string='foo', type='none')),
            start_inbound_session=dict(storage_format=dict(fields=['event_name'], user_string='foo', type='none')),
            end_inbound_session=dict(storage_format=dict(fields=['event_name'], user_string='foo', type='none')),
            end_outbound_session=dict(storage_format=dict(fields=['event_name'], user_string='foo', type='none')),
            quota_exceeded=dict(storage_format=dict(fields=['event_name'], user_string='foo', type='none')),
            errors=dict(storage_format=dict(fields=['event_name'], user_string='foo', type='none')),
        ))

        p = ModuleParameters(params=args)

        self.assertIsNone(p.nat_start_out_storage_format_fields)
        self.assertIsNone(p.nat_start_out_storage_format_user_string)
        self.assertEqual(p.nat_start_out_storage_format_type, 'none')

        self.assertIsNone(p.nat_end_out_storage_format_fields)
        self.assertIsNone(p.nat_end_out_storage_format_user_string)
        self.assertEqual(p.nat_end_out_storage_format_type, 'none')

        self.assertIsNone(p.nat_start_in_storage_format_fields)
        self.assertIsNone(p.nat_start_in_storage_format_user_string)
        self.assertEqual(p.nat_start_in_storage_format_type, 'none')

        self.assertIsNone(p.nat_end_in_storage_format_fields)
        self.assertIsNone(p.nat_end_in_storage_format_user_string)
        self.assertEqual(p.nat_end_in_storage_format_type, 'none')

        self.assertIsNone(p.nat_quota_exceeded_storage_format_fields)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_user_string)
        self.assertEqual(p.nat_quota_exceeded_storage_format_type, 'none')

        self.assertIsNone(p.nat_errors_storage_format_fields)
        self.assertIsNone(p.nat_errors_storage_format_user_string)
        self.assertEqual(p.nat_errors_storage_format_type, 'none')

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

        self.assertIn("Publisher cannot be set to", err.exception.args[0])

    def test_invalid_dns_storage_format_fields_raises(self):
        args = dict(dns_security=dict(storage_format=dict(fields=['foo'])))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.dns_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

    def test_invalid_sip_storage_format_fields_raises(self):
        args = dict(sip_security=dict(storage_format=dict(fields=['foo'])))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.sip_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

    def test_invalid_net_storage_format_fields_raises(self):
        args = dict(network_security=dict(storage_format=dict(fields=['foo'])))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.net_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

    def test_invalid_net_rate_limit_raises(self):
        args = dict(network_security=dict(rate_limit_acl_match_drop='foobar'))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.net_sec_rate_limit_acl_match_drop()

        self.assertEqual(
            "Invalid value for rate_limit_acl_match_drop must be in range 0 - 4294967295 or 'indefinite', got foobar.",
            err.exception.args[0]
        )

    def test_out_of_scope_net_rate_limit_raises(self):
        args = dict(network_security=dict(rate_limit_acl_match_drop='-1'))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.net_sec_rate_limit_acl_match_drop()

        self.assertEqual(
            "Value out of range: -1, valid rate_limit_acl_match_drop must be in range 0 - 4294967295 or 'indefinite'.",
            err.exception.args[0]
        )

    def test_invalid_nat_storage_format_fields_raises(self):
        args = dict(nat=dict(
            start_outbound_session=dict(storage_format=dict(fields=['foo'])),
            start_inbound_session=dict(storage_format=dict(fields=['foo'])),
            end_inbound_session=dict(storage_format=dict(fields=['foo'])),
            end_outbound_session=dict(storage_format=dict(fields=['foo'])),
            quota_exceeded=dict(storage_format=dict(fields=['foo'])),
            errors=dict(storage_format=dict(fields=['foo'])),

        ))

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.nat_start_out_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            p.nat_end_out_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            p.nat_start_in_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            p.nat_end_in_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            p.nat_quota_exceeded_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            p.nat_errors_storage_format_fields()

        self.assertIn('Invalid fields value, list item must be one of', err.exception.args[0])

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
        self.assertIsNone(p.nat_publisher)
        self.assertIsNone(p.nat_rate_limit_aggregate_rate)
        self.assertIsNone(p.nat_log_sub_id)
        self.assertIsNone(p.nat_lsn_legacy_mode)
        self.assertIsNone(p.nat_start_out_action)
        self.assertIsNone(p.nat_start_out_incl_dst_addr_port)
        self.assertIsNone(p.nat_rate_limit_start_out_sess)
        self.assertIsNone(p.nat_start_out_storage_format_type)
        self.assertIsNone(p.nat_start_out_storage_format_delimiter)
        self.assertIsNone(p.nat_start_out_storage_format_fields)
        self.assertIsNone(p.nat_start_out_storage_format_user_string)
        self.assertIsNone(p.nat_end_out_action)
        self.assertIsNone(p.nat_end_out_incl_dst_addr_port)
        self.assertIsNone(p.nat_rate_limit_end_out_sess)
        self.assertIsNone(p.nat_end_out_storage_format_type)
        self.assertIsNone(p.nat_end_out_storage_format_delimiter)
        self.assertIsNone(p.nat_end_out_storage_format_fields)
        self.assertIsNone(p.nat_end_out_storage_format_user_string)
        self.assertIsNone(p.nat_start_in_action)
        self.assertIsNone(p.nat_rate_limit_start_in_sess)
        self.assertIsNone(p.nat_start_in_storage_format_type)
        self.assertIsNone(p.nat_start_in_storage_format_delimiter)
        self.assertIsNone(p.nat_start_in_storage_format_fields)
        self.assertIsNone(p.nat_start_in_storage_format_user_string)
        self.assertIsNone(p.nat_end_in_action)
        self.assertIsNone(p.nat_rate_limit_end_in_sess)
        self.assertIsNone(p.nat_end_in_storage_format_type)
        self.assertIsNone(p.nat_end_in_storage_format_delimiter)
        self.assertIsNone(p.nat_end_in_storage_format_fields)
        self.assertIsNone(p.nat_end_in_storage_format_user_string)
        self.assertIsNone(p.nat_quota_exceeded_action)
        self.assertIsNone(p.nat_rate_limit_quota_exceeded)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_type)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_delimiter)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_fields)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_user_string)
        self.assertIsNone(p.nat_errors_action)
        self.assertIsNone(p.nat_rate_limit_errors)
        self.assertIsNone(p.nat_errors_storage_format_type)
        self.assertIsNone(p.nat_errors_storage_format_delimiter)
        self.assertIsNone(p.nat_errors_storage_format_fields)
        self.assertIsNone(p.nat_errors_storage_format_user_string)

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
        self.assertIsNone(p.nat_publisher)
        self.assertIsNone(p.nat_rate_limit_aggregate_rate)
        self.assertIsNone(p.nat_log_sub_id)
        self.assertIsNone(p.nat_lsn_legacy_mode)
        self.assertIsNone(p.nat_start_out_action)
        self.assertIsNone(p.nat_start_out_incl_dst_addr_port)
        self.assertIsNone(p.nat_rate_limit_start_out_sess)
        self.assertIsNone(p.nat_start_out_storage_format_type)
        self.assertIsNone(p.nat_start_out_storage_format_delimiter)
        self.assertIsNone(p.nat_start_out_storage_format_fields)
        self.assertIsNone(p.nat_start_out_storage_format_user_string)
        self.assertIsNone(p.nat_end_out_action)
        self.assertIsNone(p.nat_end_out_incl_dst_addr_port)
        self.assertIsNone(p.nat_rate_limit_end_out_sess)
        self.assertIsNone(p.nat_end_out_storage_format_type)
        self.assertIsNone(p.nat_end_out_storage_format_delimiter)
        self.assertIsNone(p.nat_end_out_storage_format_fields)
        self.assertIsNone(p.nat_end_out_storage_format_user_string)
        self.assertIsNone(p.nat_start_in_action)
        self.assertIsNone(p.nat_rate_limit_start_in_sess)
        self.assertIsNone(p.nat_start_in_storage_format_type)
        self.assertIsNone(p.nat_start_in_storage_format_delimiter)
        self.assertIsNone(p.nat_start_in_storage_format_fields)
        self.assertIsNone(p.nat_start_in_storage_format_user_string)
        self.assertIsNone(p.nat_end_in_action)
        self.assertIsNone(p.nat_rate_limit_end_in_sess)
        self.assertIsNone(p.nat_end_in_storage_format_type)
        self.assertIsNone(p.nat_end_in_storage_format_delimiter)
        self.assertIsNone(p.nat_end_in_storage_format_fields)
        self.assertIsNone(p.nat_end_in_storage_format_user_string)
        self.assertIsNone(p.nat_quota_exceeded_action)
        self.assertIsNone(p.nat_rate_limit_quota_exceeded)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_type)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_delimiter)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_fields)
        self.assertIsNone(p.nat_quota_exceeded_storage_format_user_string)
        self.assertIsNone(p.nat_errors_action)
        self.assertIsNone(p.nat_rate_limit_errors)
        self.assertIsNone(p.nat_errors_storage_format_type)
        self.assertIsNone(p.nat_errors_storage_format_delimiter)
        self.assertIsNone(p.nat_errors_storage_format_fields)
        self.assertIsNone(p.nat_errors_storage_format_user_string)


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

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {
            'publisher': '/Common/local-db-publisher', 'send_remote_challenge_failure_messages': 'no',
            'log_alarm': 'yes', 'log_block': 'no', 'log_browser': 'yes',
            'log_browser_verification_action': 'yes', 'log_captcha': 'no',
            'log_challenge_failure_request': 'yes', 'log_device_id_collection_request': 'no',
            'log_honeypot_page': 'no', 'log_mobile_application': 'no', 'log_none': 'no',
            'log_rate_limit': 'yes', 'log_redirect_to_pool': 'no', 'log_suspicious_browser': 'yes',
            'log_tcp_reset': 'no', 'log_trusted_bot': 'yes', 'log_unknown': 'yes',
            'log_untrusted_bot': 'yes'
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
            results['classification'], {'log_matches': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(
            results['dos_protection'], {'application': '/Common/local-db-publisher',
                                        'network': '/Common/local-db-publisher',
                                        'dns': '/Common/local-db-publisher', 'sip': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(results['packet_filter'], {'rate': 300, 'publisher': '/Common/local-db-publisher'})
        self.assertDictEqual(
            results['protocol_inspection'], {'log_packet': 'yes', 'publisher': '/Common/local-db-publisher'}
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
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_create_log_security_profile_with_dns_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
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
            dns_security=dict(
                publisher='local-db-publisher',
                log_dns_drop=True,
                log_dns_filtered_drop=True,
                log_dns_malformed=True,
                log_dns_malicious=True,
                log_dns_reject=True,
                storage_format=dict(
                    type='field-list',
                    delimiter='-',
                    fields=[
                        'action',
                        'attack_type',
                        'vlan',
                        'dns_query_name',
                        'dns_query_type'
                    ]
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {
            'dns_sec_publisher': '/Common/local-db-publisher', 'log_dns_drop': 'yes',
            'log_dns_filtered_drop': 'yes', 'log_dns_malformed': 'yes',
            'log_dns_malicious': 'yes', 'log_dns_reject': 'yes',
            'storage_format': {'delimiter': '-', 'type': 'field-list',
                               'fields': ['action', 'attack_type', 'vlan', 'dns_query_name', 'dns_query_type']
                               }
        }

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['description'], 'this is a log profile test')
        self.assertDictEqual(
            results['classification'], {'log_matches': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(
            results['dos_protection'], {'application': '/Common/local-db-publisher',
                                        'network': '/Common/local-db-publisher',
                                        'dns': '/Common/local-db-publisher', 'sip': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(results['packet_filter'], {'rate': 300, 'publisher': '/Common/local-db-publisher'})
        self.assertDictEqual(
            results['protocol_inspection'], {'log_packet': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertEqual(results['dns_security'], expected)

    def test_create_log_security_profile_dns_security_no_change(self, *args):
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
            ),
            dns_security=dict(
                publisher='local-db-publisher',
                log_dns_drop=True,
                log_dns_filtered_drop=True,
                log_dns_malformed=True,
                log_dns_malicious=True,
                log_dns_reject=True,
                storage_format=dict(
                    type='field-list',
                    delimiter='-',
                    fields=[
                        'action',
                        'attack_type',
                        'vlan',
                        'dns_query_name',
                        'dns_query_type'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=200, contents=load_fixture('load_log_security_profile_dns_sec.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_create_log_security_profile_with_sip_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
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
            sip_security=dict(
                publisher='local-db-publisher',
                log_sip_drop=True,
                log_sip_global_failures=True,
                log_sip_malformed=True,
                log_sip_redirect_responses=True,
                log_sip_request_failures=True,
                log_sip_server_errors=False,
                storage_format=dict(
                    type='field-list',
                    delimiter='-',
                    fields=[
                        'action',
                        'context_name',
                        'vlan',
                        'sip_callee',
                        'sip_caller'
                    ]
                )
            )
        ))

        expected = {'log_sip_drop': 'yes', 'log_sip_global_failures': 'yes', 'log_sip_malformed': 'yes',
                    'log_sip_redirect_responses': 'yes', 'log_sip_request_failures': 'yes',
                    'log_sip_server_errors': 'no', 'storage_format': {'delimiter': '-', 'type': 'field-list',
                                                                      'fields': ['action', 'context_name',
                                                                                 'vlan', 'sip_callee', 'sip_caller']}}

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['description'], 'this is a log profile test')
        self.assertDictEqual(
            results['classification'], {'log_matches': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(
            results['dos_protection'], {'application': '/Common/local-db-publisher',
                                        'network': '/Common/local-db-publisher',
                                        'dns': '/Common/local-db-publisher', 'sip': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(results['packet_filter'], {'rate': 300, 'publisher': '/Common/local-db-publisher'})
        self.assertDictEqual(
            results['protocol_inspection'], {'log_packet': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertEqual(results['sip_security'], expected)

    def test_create_log_security_profile_with_sip_security_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
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
            sip_security=dict(
                publisher='local-db-publisher',
                log_sip_drop=True,
                log_sip_global_failures=True,
                log_sip_malformed=True,
                log_sip_redirect_responses=True,
                log_sip_request_failures=True,
                log_sip_server_errors=False,
                storage_format=dict(
                    type='field-list',
                    delimiter='-',
                    fields=[
                        'action',
                        'context_name',
                        'vlan',
                        'sip_callee',
                        'sip_caller'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('load_log_security_profile_sip_sec.json')),
            dict(code=404, contents={}),
            dict(code=404, contents={}),
        ])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_create_log_security_profile_with_network_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
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
            network_security=dict(
                publisher='local-db-publisher',
                log_acl_match_accept=True,
                log_acl_match_drop=True,
                log_acl_match_reject=True,
                rate_limit_acl_match_accept='1000',
                rate_limit_acl_match_drop='indefinite',
                rate_limit_match_reject='0',
                storage_format=dict(
                    type='field-list',
                    delimiter='-',
                    fields=[
                        'acl_policy_name',
                        'acl_rule_name',
                        'date_time',
                        'action',
                        'src_ip'
                    ]
                )
            )
        ))

        expected = {
            'log_acl_match_accept': 'yes', 'log_acl_match_drop': 'yes', 'log_acl_match_reject': 'yes',
            'rate_limit_acl_match_accept': '1000', 'rate_limit_acl_match_drop': 'indefinite',
            'rate_limit_match_reject': '0', 'storage_format': {'delimiter': '-', 'type': 'field-list',
                                                               'fields': ['acl_policy_name', 'acl_rule_name',
                                                                          'date_time', 'action', 'src_ip']}
        }

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['description'], 'this is a log profile test')
        self.assertDictEqual(
            results['classification'], {'log_matches': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(
            results['dos_protection'], {'application': '/Common/local-db-publisher',
                                        'network': '/Common/local-db-publisher',
                                        'dns': '/Common/local-db-publisher', 'sip': '/Common/local-db-publisher'}
        )
        self.assertDictEqual(results['packet_filter'], {'rate': 300, 'publisher': '/Common/local-db-publisher'})
        self.assertDictEqual(
            results['protocol_inspection'], {'log_packet': 'yes', 'publisher': '/Common/local-db-publisher'}
        )
        self.assertEqual(results['network_security'], expected)

    def test_create_log_security_profile_with_network_security_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a log profile test',
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
            network_security=dict(
                publisher='local-db-publisher',
                log_acl_match_accept=True,
                log_acl_match_drop=True,
                log_acl_match_reject=True,
                rate_limit_acl_match_accept='1000',
                rate_limit_acl_match_drop='indefinite',
                rate_limit_match_reject='0',
                storage_format=dict(
                    type='field-list',
                    delimiter='-',
                    fields=[
                        'acl_policy_name',
                        'acl_rule_name',
                        'date_time',
                        'action',
                        'src_ip'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('load_log_security_profile_network.json')),
            dict(code=404, contents={}),
        ])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_create_log_security_profile_with_nat(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a nat logging profile',
            nat=dict(
                publisher='local-db-publisher',
                log_subscriber_id=True,
                rate_limit_aggregate_rate='10000',
                rate_limit_end_inbound_session='indefinite',
                rate_limit_end_outbound_session='5000',
                rate_limit_errors='6000',
                rate_limit_quota_exceeded='7000',
                rate_limit_start_inbound_session='8000',
                rate_limit_start_outbound_session='9000',
                start_outbound_session=dict(
                    action='enabled',
                    include_dest_addr_port='yes',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']
                    )
                ),
                start_inbound_session=dict(
                    action='backup-allocation-only',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']
                    )
                ),
                end_inbound_session=dict(
                    action='enabled',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']
                    )
                ),
                end_outbound_session=dict(
                    action='backup-allocation-only',
                    include_dest_addr_port='yes',
                    storage_format=dict(
                        type='user-defined',
                        user_string='foo,bar,baz'
                    )
                ),
                quota_exceeded=dict(
                    action='enabled',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['dest_ip', 'dest_port', 'protocol']
                    )
                ),
                errors=dict(
                    action='enabled',
                    storage_format=dict(
                        type='user-defined',
                        user_string='foo,bar,baz'
                    )
                )
            ),
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {
            'publisher': '/Common/local-db-publisher', 'log_subscriber_id': 'yes',
            'rate_limit_aggregate_rate': '10000', 'rate_limit_end_inbound_session': 'indefinite',
            'rate_limit_end_outbound_session': '5000', 'rate_limit_errors': '6000',
            'rate_limit_quota_exceeded': '7000', 'rate_limit_start_inbound_session': '8000',
            'rate_limit_start_outbound_session': '9000',
            'start_outbound_session': {
                'action': 'enabled', 'include_dest_addr_port': 'yes',
                'storage_format': {'delimiter': '-', 'type': 'field-list',
                                   'fields': ['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']}
            },
            'end_outbound_session': {
                'action': 'backup-allocation-only', 'include_dest_addr_port': 'yes',
                'storage_format': {'type': 'user-defined', 'user_string': 'foo,bar,baz'}
            },
            'start_inbound_session': {
                'action': 'backup-allocation-only',
                'storage_format': {'delimiter': '-', 'type': 'field-list',
                                   'fields': ['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']}
            },
            'end_inbound_session': {
                'action': 'enabled',
                'storage_format': {'delimiter': '-', 'type': 'field-list',
                                   'fields': ['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']}
            },
            'quota_exceeded': {
                'action': 'enabled',
                'storage_format': {'delimiter': '-', 'type': 'field-list',
                                   'fields': ['dest_ip', 'dest_port', 'protocol']}
            },
            'errors': {'action': 'enabled', 'storage_format': {'type': 'user-defined', 'user_string': 'foo,bar,baz'}}
        }

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(results['description'], 'this is a nat logging profile')
        self.assertDictEqual(results['nat'], expected)

    def test_create_log_security_profile_with_nat_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            description='this is a nat logging profile',
            nat=dict(
                publisher='local-db-publisher',
                log_subscriber_id=True,
                rate_limit_aggregate_rate='10000',
                rate_limit_end_inbound_session='indefinite',
                rate_limit_end_outbound_session='5000',
                rate_limit_errors='6000',
                rate_limit_quota_exceeded='7000',
                rate_limit_start_inbound_session='8000',
                rate_limit_start_outbound_session='9000',
                start_outbound_session=dict(
                    action='enabled',
                    include_dest_addr_port='yes',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']
                    )
                ),
                start_inbound_session=dict(
                    action='backup-allocation-only',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']
                    )
                ),
                end_inbound_session=dict(
                    action='enabled',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol']
                    )
                ),
                end_outbound_session=dict(
                    action='backup-allocation-only',
                    include_dest_addr_port='yes',
                    storage_format=dict(
                        type='user-defined',
                        user_string='foo,bar,baz'
                    )
                ),
                quota_exceeded=dict(
                    action='enabled',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['dest_ip', 'dest_port', 'protocol']
                    )
                ),
                errors=dict(
                    action='enabled',
                    storage_format=dict(
                        type='user-defined',
                        user_string='foo,bar,baz'
                    )
                )
            ),
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile_with_nat.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])

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
                log_alarm=False,
                log_block=True
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['bot_defense'],
                             {'send_remote_challenge_failure_messages': 'yes', 'log_alarm': 'no', 'log_block': 'yes'})
        self.assertDictEqual(results['packet_filter'], {'rate': 100})
        self.assertDictEqual(results['protocol_inspection'], {'log_packet': 'no', 'publisher': ''})

    def test_update_log_security_profile_no_change(self, *args):
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes',
                log_alarm=False,
                log_block=True
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
        mm.client.get = Mock(side_effect=[dict(
            code=200, contents=load_fixture('load_log_security_profile_changed.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_log_security_profile_dns_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes'
            ),
            dns_security=dict(
                log_dns_drop=False,
                storage_format=dict(
                    type='field-list',
                    fields=[
                        'attack_type',
                        'dns_query_name',
                        'dns_query_type'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=200, contents=load_fixture('load_log_security_profile_dns_sec.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={})
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['bot_defense'], {'send_remote_challenge_failure_messages': 'yes'})
        self.assertDictEqual(
            results['dns_security'], {'log_dns_drop': 'no',
                                      'storage_format': {'fields': ['attack_type', 'dns_query_name', 'dns_query_type']}}
        )

    def test_update_log_security_profile_create_dns_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            dns_security=dict(
                log_dns_drop=False,
                storage_format=dict(
                    type='field-list',
                    fields=[
                        'attack_type',
                        'dns_query_name',
                        'dns_query_type'
                    ]
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {
            'log_dns_drop': 'no', 'storage_format': {'type': 'field-list',
                                                     'fields': ['attack_type', 'dns_query_name', 'dns_query_type']}
        }
        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['dns_security'], expected)
        self.assertTrue(mm.client.post.called)
        self.assertEqual(mm.client.post.call_count, 1)

    def test_update_log_security_profile_dns_security_no_change(self, *args):
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes',
                log_alarm=False,
                log_block=True
            ),
            packet_filter=dict(
                rate=100
            ),
            protocol_inspection=dict(
                log_packet=False,
                publisher=''
            ),
            dns_security=dict(
                log_dns_drop=False,
                storage_format=dict(
                    type='field-list',
                    fields=[
                        'attack_type',
                        'dns_query_name',
                        'dns_query_type'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile_changed.json')),
            dict(code=200, contents=load_fixture('load_log_security_profile_dns_sec_changed.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={})
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_log_security_profile_sip_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            sip_security=dict(
                log_sip_global_failures=False,
                log_sip_malformed=False,
                storage_format=dict(
                    fields=[
                        'action',
                        'sip_callee',
                        'sip_caller'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('load_log_security_profile_sip_sec.json')),
            dict(code=404, contents={}),
            dict(code=404, contents={})
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(
            results['sip_security'], {'log_sip_global_failures': 'no', 'log_sip_malformed': 'no',
                                      'storage_format': {'fields': ['action', 'sip_callee', 'sip_caller']}}
        )

    def test_update_log_security_profile_create_sip_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            sip_security=dict(
                log_sip_global_failures=False,
                log_sip_malformed=False,
                storage_format=dict(
                    fields=[
                        'action',
                        'sip_callee',
                        'sip_caller'
                    ]
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        expected = {
            'log_sip_global_failures': 'no', 'log_sip_malformed': 'no',
            'storage_format': {'fields': ['action', 'sip_callee', 'sip_caller']}
        }

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={})
        ])
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(results['sip_security'], expected)
        self.assertTrue(mm.client.post.called)
        self.assertEqual(mm.client.post.call_count, 1)

    def test_update_log_security_profile_sip_security_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            sip_security=dict(
                log_sip_global_failures=False,
                log_sip_malformed=False,
                storage_format=dict(
                    fields=[
                        'action',
                        'sip_callee',
                        'sip_caller'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('load_log_security_profile_sip_sec_changed.json')),
            dict(code=404, contents={}),
            dict(code=404, contents={}),
        ])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_update_log_security_profile_network_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            network_security=dict(
                publisher='local-db-publisher',
                log_acl_match_drop=False,
                rate_limit_acl_match_accept='100',
                rate_limit_acl_match_drop='2000',
                rate_limit_match_reject='50',
                storage_format=dict(
                    fields=[
                        'acl_rule_name',
                        'action',
                        'src_ip'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('load_log_security_profile_network.json')),
            dict(code=404, contents={}),
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(
            results['network_security'], {'log_acl_match_drop': 'no', 'rate_limit_acl_match_accept': '100',
                                          'rate_limit_acl_match_drop': '2000', 'rate_limit_match_reject': '50',
                                          'storage_format': {'fields': ['acl_rule_name', 'action', 'src_ip']}}
        )

    def test_update_log_security_profile_create_network_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            network_security=dict(
                publisher='local-db-publisher',
                log_acl_match_drop=False,
                rate_limit_acl_match_accept='100',
                rate_limit_acl_match_drop='2000',
                rate_limit_match_reject='50',
                storage_format=dict(
                    fields=[
                        'acl_rule_name',
                        'action',
                        'src_ip'
                    ]
                )
            )
        ))

        excpected = {
            'log_acl_match_drop': 'no', 'rate_limit_acl_match_accept': '100',
            'rate_limit_acl_match_drop': '2000', 'rate_limit_match_reject': '50',
            'storage_format': {'fields': ['acl_rule_name', 'action', 'src_ip']}
        }

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(results['network_security'], excpected)
        self.assertTrue(mm.client.post.called)
        self.assertEqual(mm.client.post.call_count, 1)

    def test_update_log_security_profile_network_security_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            network_security=dict(
                publisher='local-db-publisher',
                log_acl_match_drop=False,
                rate_limit_acl_match_accept='100',
                rate_limit_acl_match_drop='2000',
                rate_limit_match_reject='50',
                storage_format=dict(
                    fields=[
                        'acl_rule_name',
                        'action',
                        'src_ip'
                    ]
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('load_log_security_profile_network_changed.json')),
            dict(code=404, contents={}),
        ])

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

        expected_call_args = {'sendRemoteChallengeFailureMessages': 'enabled', 'name': 'test_log_profile',
                              'partition': 'Common', 'localPublisher': '/Common/local-db-publisher',
                              'filter': {'logAlarm': 'enabled', 'logBlock': 'disabled', 'logBrowser': 'enabled',
                                         'logBrowserVerificationAction': 'enabled', 'logCaptcha': 'disabled',
                                         'logChallengeFailureRequest': 'enabled',
                                         'logDeviceIdCollectionRequest': 'disabled',
                                         'logHoneyPotPage': 'disabled', 'logMobileApplication': 'disabled',
                                         'logNone': 'disabled', 'logRateLimit': 'enabled',
                                         'logRedirectToPool': 'disabled', 'logSuspiciousBrowser': 'enabled',
                                         'logTcpReset': 'disabled', 'logTrustedBot': 'enabled', 'logUnknown': 'enabled',
                                         'logUntrustedBot': 'enabled'
                                         }
                              }

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_dns_security_from_device = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}), dict(code=404, contents={})
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(results['bot_defense'], {'send_remote_challenge_failure_messages': 'yes'})
        self.assertDictEqual(mm.client.patch.call_args_list[0][1]['data']['botDefense'][0], expected_call_args)

    def test_update_log_security_profile_with_nat(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            nat=dict(
                log_subscriber_id=False,
                rate_limit_aggregate_rate='3000000',
                rate_limit_end_inbound_session='500000',
                start_outbound_session=dict(
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['dest_ip', 'dest_port', 'context_name', 'event_name', 'protocol']
                    )
                ),
                end_inbound_session=dict(
                    action='enabled',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['dest_ip', 'dest_port']
                    )
                ),
                quota_exceeded=dict(
                    storage_format=dict(
                        delimiter=';',
                    )
                ),
                errors=dict(
                    action='enabled',
                    storage_format=dict(
                        type='field-list',
                        fields=['dest_ip', 'dest_port', 'protocol']
                    )
                )
            ),
        )
        )

        expected = {
            'log_subscriber_id': 'no', 'rate_limit_aggregate_rate': '3000000',
            'rate_limit_end_inbound_session': '500000',
            'start_outbound_session': {
                'storage_format': {'fields': ['dest_ip', 'dest_port', 'context_name', 'event_name', 'protocol']}
            },
            'end_inbound_session': {
                'storage_format': {'fields': ['dest_ip', 'dest_port']}
            },
            'quota_exceeded': {
                'storage_format': {'delimiter': ';'}
            },
            'errors': {
                'storage_format': {'type': 'field-list', 'fields': ['dest_ip', 'dest_port', 'protocol']}
            }
        }

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile_with_nat.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(results['nat'], expected)

    def test_update_log_security_profile_with_nat_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            nat=dict(
                log_subscriber_id=False,
                rate_limit_aggregate_rate='3000000',
                rate_limit_end_inbound_session='500000',
                start_outbound_session=dict(
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['dest_ip', 'dest_port', 'context_name', 'event_name', 'protocol']
                    )
                ),
                end_inbound_session=dict(
                    action='enabled',
                    storage_format=dict(
                        delimiter='-',
                        type='field-list',
                        fields=['dest_ip', 'dest_port']
                    )
                ),
                quota_exceeded=dict(
                    storage_format=dict(
                        delimiter=';',
                    )
                ),
                errors=dict(
                    action='enabled',
                    storage_format=dict(
                        type='field-list',
                        fields=['dest_ip', 'dest_port', 'protocol']
                    )
                )
            ),
        )
        )
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile_with_nat_changed.json')),
            dict(code=404, contents={}), dict(code=404, contents={}),
            dict(code=404, contents={}), dict(code=404, contents={}),
        ])

        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_create_log_security_profile_create_application_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_appsec_log_profile',
            application_security=dict(
                config=dict(
                    remote_storage='remote',
                    response_logging='illegal',
                    protocol='tcp',
                    servers=[dict(ip='11.22.33.44', port=443)],
                    facility='local0',
                    storage_format=dict(
                        delimiter=',',
                        type='predefined',
                        fields=['date_time', 'conviction_traps']
                    ),
                    max_entry_length='2k',
                    report_anomalies='enabled',
                    report_challenge_failure='enabled'
                ),
                storage_filter=dict(
                    logic_operation='or',
                    request_type='all',
                    log_challenge_failure_requests='enabled',
                    protocols=['http', 'wss'],
                    resp_status_codes=['101', '102'],
                    http_methods=['UNLINK', 'TRACE'],
                    login_result=['login-result-successful'],
                    search_in='query-string',
                    search_string='BasicAuth'
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_create_log_security_profile_update_application_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_appsec_log_profile',
            application_security=dict(
                config=dict(
                    remote_storage='remote',
                    response_logging='illegal',
                    protocol='tcp',
                    servers=[dict(ip='11.22.33.44', port=443)],
                    facility='local0',
                    storage_format=dict(
                        delimiter=',',
                        type='predefined',
                        fields=['date_time', 'conviction_traps']
                    ),
                    max_entry_length='6k',
                    report_anomalies='enabled',
                    report_challenge_failure='enabled'
                ),
                storage_filter=dict(
                    logic_operation='or',
                    request_type='all',
                    log_challenge_failure_requests='enabled',
                    protocols=['http', 'wss'],
                    resp_status_codes=['101', '102', '400'],
                    http_methods=['UNLINK', 'TRACE', 'ACL'],
                    login_result=['login-result-successful'],
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        existing = load_fixture('load_log_security_profile_application.json')

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        mm.read_dns_security_from_device = Mock(return_value=None)
        mm.read_network_security_from_device = Mock(return_value=None)
        mm.read_sip_security_from_device = Mock(return_value=None)

        mm.client.get = Mock(return_value=existing)

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)

    def test_create_log_security_profile_update_application_security_no_change(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_appsec_log_profile',
            application_security=dict(
                config=dict(
                    remote_storage='remote',
                    response_logging='illegal',
                    protocol='tcp',
                    servers=[dict(ip='11.22.33.44', port=443)],
                    facility='local2',
                    storage_format=dict(
                        delimiter=',',
                        type='predefined',
                        fields=[
                            'blocking_exception_reason',
                            'date_time',
                            'conviction_traps'
                        ]
                    ),
                    max_entry_length='10k',
                    report_anomalies='enabled',
                    report_challenge_failure='enabled'
                ),
                storage_filter=dict(
                    logic_operation='or',
                    request_type='all',
                    log_challenge_failure_requests='enabled',
                    protocols=['http', 'wss'],
                    resp_status_codes=['101', '102'],
                    http_methods=['UNLINK', 'TRACE', 'SEARCH'],
                    login_result=['login-result-successful'],
                )
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        existing = load_fixture('load_log_security_profile_application.json')

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        mm.read_dns_security_from_device = Mock(return_value=None)
        mm.read_network_security_from_device = Mock(return_value=None)
        mm.read_sip_security_from_device = Mock(return_value=None)

        mm.client.get = Mock(return_value=existing)

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 0)

    def test_create_log_security_profile_delete_application_security(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_appsec_log_profile',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        existing = load_fixture('load_log_security_profile_application.json')

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)

    def test_update_log_security_profile_fails(self, *args):
        # Configure the arguments that would be sent to the Ansible module
        set_module_args(dict(
            name='test_log_profile',
            bot_defense=dict(
                send_remote_challenge_failure_messages='yes',
                log_alarm=False,
                log_block=True
            )
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_dns_security_from_device = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_log_security_profile.json')),
            dict(code=404, contents={}), dict(code=404, contents={}), dict(code=404, contents={})
        ])
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

        mm.client.post = Mock(side_effect=[
            dict(code=500, contents='server error'), dict(code=403, contents='forbidden'),
            dict(code=401, contents='access denied')
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm._create_dns_security(dict())
        self.assertIn('server error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm._create_sip_security(dict())
        self.assertIn('forbidden', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm._create_net_security(dict())
        self.assertIn('access denied', err.exception.args[0])

        mm.client.patch = Mock(side_effect=[
            dict(code=401, contents='access denied'),
            dict(code=403, contents='forbidden'),
            dict(code=500, contents='server error')
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm._update_dns_security(dict())
        self.assertIn('access denied', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm._update_sip_security(dict())
        self.assertIn('forbidden', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm._update_net_security(dict())
        self.assertIn('server error', err.exception.args[0])

        mm.client.get = Mock(side_effect=[
            dict(code=403, contents='forbidden'),
            dict(code=401, contents='access denied'),
            dict(code=500, contents='server error')
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.read_dns_security_from_device()
        self.assertIn('forbidden', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm.read_sip_security_from_device()
        self.assertIn('access denied', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            mm.read_network_security_from_device()
        self.assertIn('server error', err.exception.args[0])
