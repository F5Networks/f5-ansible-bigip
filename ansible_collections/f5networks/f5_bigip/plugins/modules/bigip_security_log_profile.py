#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_security_log_profile
short_description: Manage security log profiles on a BIG-IP
description:
  - Manage security log profiles on a BIG-IP.
version_added: 1.13.0
options:
  name:
    description:
      - Specifies the name of the security log profile to manage.
    type: str
    required: true
  description:
    description:
      - Specifies descriptive text that identifies security log profile.
    type: str
  auto_discovery:
    description:
      - "Specifies log publisher that the system uses to log Auto Discovered Service/Server events."
      - Defines log publisher as configured on the BIG-IP.
      - "If desired log publisher is configured on a different partition to where log profile is created
        a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
    type: str
  dos_protection:
    description:
      - Defines the log publishers used by the system to log detected DoS attacks.
    type: dict
    suboptions:
      application:
        description:
          - Defines the log publisher used to log Application DoS attacks.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      network:
        description:
          - Specifies the name of the log publisher used for logging Network DoS events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      dns:
        description:
          - Specifies the name of the log publisher used for logging DNS DoS events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      sip:
        description:
          - Specifies the name of the log publisher used for logging SIP DoS events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
  bot_defense:
    description:
      - Configures system logging of events from the Bot Defense mechanism.
      - When configuring a new profile with C(bot_defense) both C(publisher) and C(filter) must be specified.
    type: dict
    suboptions:
      publisher:
        description:
          - Specifies the name of the local log publisher used for Bot Defense log messages.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      send_remote_challenge_failure_messages:
        description:
          - "to be determined"
        type: bool
      filter:
        description:
          - Configures a set of logging options for the HTTP client.
          - When configuring at least one of the options must be set to C(yes).
          - Parameter is mandatory when creating a new profile with C(bot_defense) logging.
        type: dict
        suboptions:
          log_alarm:
            description:
              - Enable/Disable logging of requests triggering ALARM mitigation
                action of the Bot Defense logging profile.
            type: bool
          log_block:
            description:
              - Enable/Disable logging of requests triggering Block mitigation
                action of the Bot Defense logging profile.
            type: bool
          log_browser:
            description:
              - "TBD"
            type: bool
          log_browser_verification_action:
            description:
              - "TBD"
            type: bool
          log_captcha:
            description:
              - "TBD"
            type: bool
          log_challenge_failure_request:
            description:
              - "TBD"
            type: bool
          log_device_id_collection_request:
            description:
              - "TBD"
            type: bool
          log_honeypot_page:
            description:
              - "TBD"
            type: bool
          log_mobile_application:
            description:
              - "TBD"
            type: bool
          log_none:
            description:
              - "TBD"
            type: bool
          log_rate_limit:
            description:
              - "TBD"
            type: bool
          log_redirect_to_pool:
            description:
              - "TBD"
            type: bool
          log_suspicious_browser:
            description:
              - "TBD"
            type: bool
          log_tcp_reset:
            description:
              - "TBD"
            type: bool
          log_trusted_bot:
            description:
              - "TBD"
            type: bool
          log_unknown:
            description:
              - "TBD"
            type: bool
          log_untrusted_bot:
            description:
              - "TBD"
            type: bool
  protocol_inspection:
    description:
      - Configures system logging of events from the Protocol Inspection engine.
    type: dict
    suboptions:
      log_packet:
        description:
          - Enables/Disables logging of packet payload for Protocol Inspection events.
        type: bool
      publisher:
        description:
          - Specifies the name of the log publisher used for logging of Protocol Inspection events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
  packet_filter:
    description:
      - Configures logging of IPv6 Extension Header Packet Filter rule match events.
    type: dict
    suboptions:
      rate:
        description:
          - "TBD"
          - "Valid value range is from 1 to 1000 messages/sec"
        type: int
      publisher:
        description:
          - Specifies the name of the log publisher used for logging of IPv6 Extension Header Packet Filter
            rule match events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
  classification:
    description:
      - Configures logging of events from the Classification engine.
    type: dict
    suboptions:
      log_matches:
        description:
          - "TBD"
        type: bool
      publisher:
        description:
          - Specifies the name of the log publisher used for logging of Classification engine events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the security log profile is created.
      - When C(absent), ensures the security log profile is removed.
    type: str
    choices:
      - absent
      - present
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- hosts: all
  collections:
    - f5networks.f5_bigip
  connection: httpapi

  vars:
    ansible_host: "lb.mydomain.com"
    ansible_user: "admin"
    ansible_httpapi_password: "secret"
    ansible_network_os: f5networks.f5_bigip.bigip
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Create a security log profile
      bigip_security_log_profile:
        name: "test_log_profile"
        description: "this is a log profile test"
        auto_discovery: "local-db-publisher"
        dos_protection:
          application: "local-db-publisher"
          network: "local-db-publisher"
        protocol_inspection:
          log_packet: "yes"
          publisher: "local-db-publisher"
        packet_filter:
          rate: 300
          publisher: "local-db-publisher"
        bot_defense:
          publisher: "local-db-publisher"
          filter:
            log_alarm: "yes"
            log_browser: "yes"

    - name: Modify a security log profile
      bigip_security_log_profile:
        name: "test_log_profile"
        packet_filter:
          rate: 100
        bot_defense:
          filter:
            log_alarm: "no"

    - name: Delete a security log profile
      bigip_security_log_profile:
        name: "test_log_profile"
        state: absent
'''

RETURN = r'''
# only common fields returned
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, fq_name, flatten_boolean, transform_name
)
from ..module_utils.compare import cmp_str_with_none


class Parameters(AnsibleF5Parameters):
    api_map = {
        'dosApplication': 'dos_app',
        'dosNetworkPublisher': 'dos_net_pub',
        'autoDiscovery': 'auto_discovery',
        'protocolSipDosPublisher': 'dos_sip_pub',
        'protocolDnsDosPublisher': 'dos_dns_pub',
        'protocolInspection': 'protocol_inspect',
        'packetFilter': 'packet_filter',
        'botDefense': 'bot_defense'
    }

    api_attributes = [
        'description',
        'dosApplication',
        'dosNetworkPublisher',
        'protocolSipDosPublisher',
        'protocolDnsDosPublisher',
        'protocolInspection',
        'autoDiscovery',
        'classification',
        'packetFilter',
        'botDefense'
    ]

    returnables = [
        'auto_discovery',
        'description',
        'dos_app_publisher',
        'dos_net_pub',
        'dos_dns_pub',
        'dos_sip_pub',
        'proto_inspect_log',
        'proto_inspect_pub',
        'packet_filter_rate',
        'packet_filter_pub',
        'classification_log',
        'classification_pub',
        'bot_publisher',
        'bot_remote_chall_fail_msg',
        'bot_log_alarm',
        'bot_log_block',
        'bot_log_browser',
        'bot_log_browser_verify',
        'bot_log_captcha',
        'bot_log_challenge_failure',
        'bot_log_deviceid_coll_req',
        'bot_log_honey_pot',
        'bot_log_mobile_app',
        'bot_log_none',
        'bot_log_rate_limit',
        'bot_log_redirect_to_pool',
        'bot_log_suspect_browser',
        'bot_log_tcp_reset',
        'bot_log_trusted_bot',
        'bot_log_unknown',
        'bot_log_untrusted_bot'
    ]

    updatables = [
        'auto_discovery',
        'description',
        'dos_app_publisher',
        'dos_net_pub',
        'dos_dns_pub',
        'dos_sip_pub',
        'proto_inspect_log',
        'proto_inspect_pub',
        'packet_filter_rate',
        'packet_filter_pub',
        'classification_log',
        'classification_pub',
        'bot_publisher',
        'bot_remote_chall_fail_msg',
        'bot_log_alarm',
        'bot_log_block',
        'bot_log_browser',
        'bot_log_browser_verify',
        'bot_log_captcha',
        'bot_log_challenge_failure',
        'bot_log_deviceid_coll_req',
        'bot_log_honey_pot',
        'bot_log_mobile_app',
        'bot_log_none',
        'bot_log_rate_limit',
        'bot_log_redirect_to_pool',
        'bot_log_suspect_browser',
        'bot_log_tcp_reset',
        'bot_log_trusted_bot',
        'bot_log_unknown',
        'bot_log_untrusted_bot'
    ]


class ApiParameters(Parameters):
    @property
    def auto_discovery(self):
        if self._values['auto_discovery'] is None:
            return None
        return self._values['auto_discovery'].get('logPublisher')

    @property
    def dos_app_publisher(self):
        if self._values['dos_app'] is None:
            return None
        return self._values['dos_app'][0].get('localPublisher')

    @property
    def proto_inspect_log(self):
        if self._values['protocol_inspect'] is None:
            return None
        return self._values['protocol_inspect'].get('logPacket')

    @property
    def proto_inspect_pub(self):
        if self._values['protocol_inspect'] is None:
            return None
        return self._values['protocol_inspect'].get('logPublisher')

    @property
    def packet_filter_rate(self):
        if self._values['packet_filter'] is None:
            return None
        return self._values['packet_filter'].get('aggregateRate')

    @property
    def packet_filter_pub(self):
        if self._values['packet_filter'] is None:
            return None
        return self._values['packet_filter'].get('logPublisher')

    @property
    def classification_pub(self):
        if self._values['classification'] is None:
            return None
        return self._values['classification'].get('logPublisher')

    @property
    def classification_log(self):
        if self._values['classification'] is None:
            return None
        return self._values['classification'].get('logAllClassificationMatches')

    @property
    def bot_publisher(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0].get('localPublisher')

    @property
    def bot_remote_chall_fail_msg(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0].get('sendRemoteChallengeFailureMessages')

    @property
    def bot_log_alarm(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logAlarm')

    @property
    def bot_log_block(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logBlock')

    @property
    def bot_log_browser(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logBrowser')

    @property
    def bot_log_browser_verify(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logBrowserVerificationAction')

    @property
    def bot_log_captcha(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logCaptcha')

    @property
    def bot_log_challenge_failure(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logChallengeFailureRequest')

    @property
    def bot_log_deviceid_coll_req(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logDeviceIdCollectionRequest')

    @property
    def bot_log_honey_pot(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logHoneyPotPage')

    @property
    def bot_log_mobile_app(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logMobileApplication')

    @property
    def bot_log_none(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logNone')

    @property
    def bot_log_rate_limit(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logRateLimit')

    @property
    def bot_log_redirect_to_pool(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logRedirectToPool')

    @property
    def bot_log_suspect_browser(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logSuspiciousBrowser')

    @property
    def bot_log_tcp_reset(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logTcpReset')

    @property
    def bot_log_trusted_bot(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logTrustedBot')

    @property
    def bot_log_unknown(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logUnknown')

    @property
    def bot_log_untrusted_bot(self):
        if self._values['bot_defense'] is None:
            return None
        return self._values['bot_defense'][0]['filter'].get('logUntrustedBot')

    @property
    def bot_defense_exists(self):
        if self._values['bot_defense'] is None:
            return False
        return True


class ModuleParameters(Parameters):
    @staticmethod
    def _handle_booleans(item):
        result = flatten_boolean(item)
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    def _handle_publishers(self, item):
        if item == '':
            return ''
        return fq_name(self.partition, item)

    @property
    def auto_discovery(self):
        return self._handle_publishers(self._values['auto_discovery'])

    @property
    def dos_app_publisher(self):
        if self._values['dos_protection'] is None:
            return None
        return self._handle_publishers(self._values['dos_protection'].get('application'))

    @property
    def dos_net_pub(self):
        if self._values['dos_protection'] is None:
            return None
        return self._handle_publishers(self._values['dos_protection'].get('network'))

    @property
    def dos_dns_pub(self):
        if self._values['dos_protection'] is None:
            return None
        return self._handle_publishers(self._values['dos_protection'].get('dns'))

    @property
    def dos_sip_pub(self):
        if self._values['dos_protection'] is None:
            return None
        return self._handle_publishers(self._values['dos_protection'].get('sip'))

    @property
    def proto_inspect_log(self):
        if self._values['protocol_inspection'] is None:
            return None
        return self._handle_booleans(self._values['protocol_inspection'].get('log_packet'))

    @property
    def proto_inspect_pub(self):
        if self._values['protocol_inspection'] is None:
            return None
        return self._handle_publishers(self._values['protocol_inspection'].get('publisher'))

    @property
    def packet_filter_rate(self):
        if self._values['packet_filter'] is None:
            return None
        rate = self._values['packet_filter'].get('rate')
        if rate:
            if rate < 1 or rate > 1000:
                raise F5ModuleError(
                    "The packet filter rate value must be between 1 and 1000 messages per second."
                )
        return rate

    @property
    def packet_filter_pub(self):
        if self._values['packet_filter'] is None:
            return None
        return self._handle_publishers(self._values['packet_filter'].get('publisher'))

    @property
    def classification_log(self):
        if self._values['classification'] is None:
            return None
        return self._handle_booleans(self._values['classification'].get('log_matches'))

    @property
    def classification_pub(self):
        if self._values['classification'] is None:
            return None
        return self._handle_publishers(self._values['classification'].get('publisher'))

    @property
    def bot_publisher(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('publisher') == '':
            raise F5ModuleError(
                f"Publisher cannot be set to {self._values['bot_defense'].get('publisher')} "
                f"when configuring bot defense logging."
            )
        return fq_name(self.partition, self._values['bot_defense'].get('publisher'))

    @property
    def bot_remote_chall_fail_msg(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('send_remote_challenge_failure_messages'))

    @property
    def bot_log_alarm(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_alarm'))

    @property
    def bot_log_block(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_block'))

    @property
    def bot_log_browser(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_browser'))

    @property
    def bot_log_browser_verify(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_browser_verification_action'))

    @property
    def bot_log_captcha(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_captcha'))

    @property
    def bot_log_challenge_failure(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_challenge_failure_request'))

    @property
    def bot_log_deviceid_coll_req(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_device_id_collection_request'))

    @property
    def bot_log_honey_pot(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_honeypot_page'))

    @property
    def bot_log_mobile_app(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_mobile_application'))

    @property
    def bot_log_none(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_none'))

    @property
    def bot_log_rate_limit(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_rate_limit'))

    @property
    def bot_log_redirect_to_pool(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_redirect_to_pool'))

    @property
    def bot_log_suspect_browser(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_suspicious_browser'))

    @property
    def bot_log_tcp_reset(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_tcp_reset'))

    @property
    def bot_log_trusted_bot(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_trusted_bot'))

    @property
    def bot_log_unknown(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_unknown'))

    @property
    def bot_log_untrusted_bot(self):
        if self._values['bot_defense'] is None:
            return None
        if self._values['bot_defense'].get('filter'):
            return self._handle_booleans(self._values['bot_defense']['filter'].get('log_untrusted_bot'))


class Changes(Parameters):
    def to_return(self):  # pragma: no cover
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    @property
    def auto_discovery(self):
        if self._values['auto_discovery'] is None:
            return None
        result = dict(
            logPublisher=self._values['auto_discovery']
        )
        return result

    @property
    def classification(self):
        result = self._filter_params(
            dict(logAllClassificationMatches=self._values['classification_log'],
                 logPublisher=self._values['classification_pub'])
        )
        if result:
            return result

    @property
    def dos_app(self):
        if self._values['dos_app_publisher'] is None:
            return None
        result = list()
        element = self._filter_params(dict(localPublisher=self._values['dos_app_publisher']))
        if element:
            result.append(element)
        if result:
            return result

    @property
    def protocol_inspect(self):
        tmp = dict(logPacket=self._values['proto_inspect_log'], logPublisher=self._values['proto_inspect_pub'])
        result = self._filter_params(tmp)
        if result:
            return result

    @property
    def packet_filter(self):
        tmp = dict(aggregateRate=self._values['packet_filter_rate'], logPublisher=self._values['packet_filter_pub'])
        result = self._filter_params(tmp)
        if result:
            return result

    @property
    def bot_defense(self):
        result = list()
        tmp_filter = dict(
            logAlarm=self._values['bot_log_alarm'],
            logBlock=self._values['bot_log_block'],
            logBrowser=self._values['bot_log_browser'],
            logBrowserVerificationAction=self._values['bot_log_browser_verify'],
            logCaptcha=self._values['bot_log_captcha'],
            logChallengeFailureRequest=self._values['bot_log_challenge_failure'],
            logDeviceIdCollectionRequest=self._values['bot_log_deviceid_coll_req'],
            logHoneyPotPage=self._values['bot_log_honey_pot'],
            logMobileApplication=self._values['bot_log_mobile_app'],
            logNone=self._values['bot_log_none'],
            logRateLimit=self._values['bot_log_rate_limit'],
            logRedirectToPool=self._values['bot_log_redirect_to_pool'],
            logSuspiciousBrowser=self._values['bot_log_suspect_browser'],
            logTcpReset=self._values['bot_log_tcp_reset'],
            logTrustedBot=self._values['bot_log_trusted_bot'],
            logUnknown=self._values['bot_log_unknown'],
            logUntrustedBot=self._values['bot_log_untrusted_bot'],
        )
        log_filter = self._filter_params(tmp_filter)
        element = self._filter_params(
            dict(localPublisher=self._values['bot_publisher'],
                 sendRemoteChallengeFailureMessages=self._values['bot_remote_chall_fail_msg'])
        )
        if log_filter:
            element['filter'] = log_filter
        if element:
            result.append(element)
            return result


class ReportableChanges(Changes):
    returnables = [
        'auto_discovery',
        'bot_defense',
        'classification',
        'description',
        'dos_protection',
        'packet_filter',
        'protocol_inspection'
    ]

    @property
    def auto_discovery(self):
        if self._values['auto_discovery'] is None:
            return None
        return self._values['auto_discovery'].get('logPublisher')

    @property
    def bot_defense(self):
        tmp_filter = dict(
            log_alarm=self._values['bot_log_alarm'],
            log_block=self._values['bot_log_block'],
            log_browser=self._values['bot_log_browser'],
            log_browser_verification_action=self._values['bot_log_browser_verify'],
            log_captcha=self._values['bot_log_captcha'],
            log_challenge_failure_request=self._values['bot_log_challenge_failure'],
            log_device_id_collection_request=self._values['bot_log_deviceid_coll_req'],
            log_honeypot_page=self._values['bot_log_honey_pot'],
            log_mobile_application=self._values['bot_log_mobile_app'],
            log_none=self._values['bot_log_none'],
            log_rate_limit=self._values['bot_log_rate_limit'],
            log_redirect_to_pool=self._values['bot_log_redirect_to_pool'],
            log_suspicious_browser=self._values['bot_log_suspect_browser'],
            log_tcp_reset=self._values['bot_log_tcp_reset'],
            log_trusted_bot=self._values['bot_log_trusted_bot'],
            log_unknown=self._values['bot_log_unknown'],
            log_untrusted_bot=self._values['bot_log_untrusted_bot']
        )
        log_filter = self._filter_params(tmp_filter)
        result = self._filter_params(
            dict(publisher=self._values['bot_publisher'],
                 send_remote_challenge_failure_messages=self._values['bot_remote_chall_fail_msg'])
        )
        if log_filter:
            result['filter'] = log_filter
        if result:
            return result

    @property
    def classification(self):
        result = self._filter_params(
            dict(log_matches=self._values['classification_log'], publisher=self._values['classification_pub'])
        )
        if result:
            return result

    @property
    def dos_protection(self):
        result = self._filter_params(
            dict(application=self._values['dos_app_publisher'], network=self._values['dos_net_pub'],
                 dns=self._values['dos_dns_pub'], sip=self._values['dos_sip_pub'])
        )
        if result:
            return result

    @property
    def packet_filter(self):
        result = self._filter_params(
            dict(rate=self._values['packet_filter_rate'], publisher=self._values['packet_filter_pub'])
        )
        if result:
            return result

    @property
    def protocol_inspection(self):
        result = self._filter_params(
            dict(log_packet=self._values['proto_inspect_log'], publisher=self._values['proto_inspect_pub'])
        )
        if result:
            return result


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:  # pragma: no cover
            return attr1

    @property
    def auto_discovery(self):
        return cmp_str_with_none(self.want.auto_discovery, self.have.auto_discovery)

    @property
    def dos_app_publisher(self):
        return cmp_str_with_none(self.want.dos_app_publisher, self.have.dos_app_publisher)

    @property
    def dos_net_pub(self):
        return cmp_str_with_none(self.want.dos_net_pub, self.have.dos_net_pub)

    @property
    def dos_dns_pub(self):
        return cmp_str_with_none(self.want.dos_dns_pub, self.have.dos_dns_pub)

    @property
    def dos_sip_pub(self):
        return cmp_str_with_none(self.want.dos_sip_pub, self.have.dos_sip_pub)

    @property
    def proto_inspect_pub(self):
        return cmp_str_with_none(self.want.proto_inspect_pub, self.have.proto_inspect_pub)

    @property
    def packet_filter_pub(self):
        return cmp_str_with_none(self.want.packet_filter_pub, self.have.packet_filter_pub)

    @property
    def classification_pub(self):
        return cmp_str_with_none(self.want.classification_pub, self.have.classification_pub)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):  # pragma: no cover
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        start = datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def _add_missing_options(self, params):
        # adds the config identifiers and other objects required by the API, we mirror GUI behavior just by using
        # name and partition of main resource
        if 'dosApplication' in params:
            params['dosApplication'][0]['name'] = self.want.name
            params['dosApplication'][0]['partition'] = self.want.partition

        if 'botDefense' in params:
            params['botDefense'][0]['name'] = self.want.name
            params['botDefense'][0]['partition'] = self.want.partition

            if self.have.bot_defense_exists:
                if not params['botDefense'][0].get('localPublisher'):
                    params['botDefense'][0]['localPublisher'] = self.have.bot_publisher
                params['botDefense'][0]['filter'] = self._add_existing_filters_if_needed()
        return params

    def _add_existing_filters_if_needed(self):
        # this is necessary as even with PATCH where we modify one entry entire filter object must be sent
        log_filter = dict(
            logAlarm=self.changes.bot_log_alarm if self.changes.bot_log_alarm else self.have.bot_log_alarm,
            logBlock=self.changes.bot_log_block if self.changes.bot_log_block else self.have.bot_log_block,
            logBrowser=self.changes.bot_log_browser if self.changes.bot_log_browser else self.have.bot_log_browser,
            logBrowserVerificationAction=self.changes.bot_log_browser_verify
            if self.changes.bot_log_browser_verify else self.have.bot_log_browser_verify,
            logCaptcha=self.changes.bot_log_captcha if self.changes.bot_log_captcha else self.have.bot_log_captcha,
            logChallengeFailureRequest=self.changes.bot_log_challenge_failure
            if self.changes.bot_log_challenge_failure else self.have.bot_log_challenge_failure,
            logDeviceIdCollectionRequest=self.changes.bot_log_deviceid_coll_req
            if self.changes.bot_log_deviceid_coll_req else self.have.bot_log_deviceid_coll_req,
            logHoneyPotPage=self.changes.bot_log_honey_pot
            if self.changes.bot_log_honey_pot else self.have.bot_log_honey_pot,
            logMobileApplication=self.changes.bot_log_mobile_app
            if self.changes.bot_log_mobile_app else self.have.bot_log_mobile_app,
            logNone=self.changes.bot_log_none if self.changes.bot_log_none else self.have.bot_log_none,
            logRateLimit=self.changes.bot_log_rate_limit
            if self.changes.bot_log_rate_limit else self.have.bot_log_rate_limit,
            logRedirectToPool=self.changes.bot_log_redirect_to_pool
            if self.changes.bot_log_redirect_to_pool else self.have.bot_log_redirect_to_pool,
            logSuspiciousBrowser=self.changes.bot_log_suspect_browser
            if self.changes.bot_log_suspect_browser else self.have.bot_log_suspect_browser,
            logTcpReset=self.changes.bot_log_tcp_reset
            if self.changes.bot_log_tcp_reset else self.have.bot_log_tcp_reset,
            logTrustedBot=self.changes.bot_log_trusted_bot
            if self.changes.bot_log_trusted_bot else self.have.bot_log_trusted_bot,
            logUnknown=self.changes.bot_log_unknown
            if self.changes.bot_log_unknown else self.have.bot_log_unknown,
            logUntrustedBot=self.changes.bot_log_untrusted_bot
            if self.changes.bot_log_untrusted_bot else self.have.bot_log_untrusted_bot
        )
        return log_filter

    def create_on_device(self):
        params = self._add_missing_options(self.changes.api_params())
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "/mgmt/tm/security/log/profile/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self._add_missing_options(self.changes.api_params())
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            description=dict(),
            auto_discovery=dict(),
            dos_protection=dict(
                type='dict',
                options=dict(
                    application=dict(),
                    network=dict(),
                    dns=dict(),
                    sip=dict()
                )
            ),
            bot_defense=dict(
                type='dict',
                options=dict(
                    publisher=dict(),
                    send_remote_challenge_failure_messages=dict(type='bool'),
                    filter=dict(
                        type='dict',
                        options=dict(
                            log_alarm=dict(type='bool'),
                            log_block=dict(type='bool'),
                            log_browser=dict(type='bool'),
                            log_browser_verification_action=dict(type='bool'),
                            log_captcha=dict(type='bool'),
                            log_challenge_failure_request=dict(type='bool'),
                            log_device_id_collection_request=dict(type='bool'),
                            log_honeypot_page=dict(type='bool'),
                            log_mobile_application=dict(type='bool'),
                            log_none=dict(type='bool'),
                            log_rate_limit=dict(type='bool'),
                            log_redirect_to_pool=dict(type='bool'),
                            log_suspicious_browser=dict(type='bool'),
                            log_tcp_reset=dict(type='bool'),
                            log_trusted_bot=dict(type='bool'),
                            log_unknown=dict(type='bool'),
                            log_untrusted_bot=dict(type='bool'),
                        ),
                        required_one_of=[
                            ['log_alarm', 'log_block', 'log_browser', 'log_browser_verification_action',
                             'log_captcha', 'log_challenge_failure_request', 'log_device_id_collection_request',
                             'log_honeypot_page', 'log_mobile_application', 'log_none', 'log_rate_limit',
                             'log_redirect_to_pool', 'log_suspicious_browser', 'log_tcp_reset', 'log_trusted_bot',
                             'log_unknown', 'log_untrusted_bot']
                        ]
                    ),
                ),

            ),
            protocol_inspection=dict(
                type='dict',
                options=dict(
                    log_packet=dict(type='bool'),
                    publisher=dict()
                )
            ),
            packet_filter=dict(
                type='dict',
                options=dict(
                    rate=dict(type='int'),
                    publisher=dict()
                )
            ),
            classification=dict(
                type='dict',
                options=dict(
                    log_matches=dict(type='bool'),
                    publisher=dict()
                )
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
