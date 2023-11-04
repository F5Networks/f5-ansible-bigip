#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
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
          - Defines the log publisher used for log Application DoS attacks.
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
      - When configuring a new profile with C(bot_defense) both C(publisher) and one of C(log_*)
        options must be specified.
      - When modifying a profile's C(bot_defense) settings at least one C(log_*) options must remain set to C(yes)
        on the device. In case when during modify operation the device returns an API errors user
        must consult device configuration to determine if the selected option can be set to C(no).
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
  dns_security:
    description:
      - Configures the system to log dropped, malformed, or rejected requests for DNS Security.
    type: dict
    suboptions:
      publisher:
        description:
          - Specifies the name of the log publisher used for logging DNS security events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      log_dns_drop:
        description:
          - Enable/Disable logging of dropped DNS requests.
        type: bool
      log_dns_filtered_drop:
        description:
          - Enable/Disable logging of DNS requests dropped due to DNS query/header-opcode filtering.
          - The system does not log DNS requests that are dropped due to errors in the way the system
            processes DNS packets.
        type: bool
      log_dns_malformed:
        description:
          - Enable/Disable logging of malformed DNS requests.
        type: bool
      log_dns_malicious:
        description:
          - Enable/Disable logging of malicious DNS requests.
        type: bool
      log_dns_reject:
        description:
          - Enable/Disable logging of rejected DNS requests.
        type: bool
      storage_format:
        description:
          - Configures custom formatting of DNS security log messages.
        type: dict
        suboptions:
          type:
            description:
              - Specifies the format type for log messages.
              - When set to C(none) the system uses default format type to log the messages to a Remote Syslog server.
              - When set to C(field-list) the system uses a set of fields, set in a specific order, to log messages.
              - When set to C(user-defined) the system uses to log messages is in the form of a user-defined string.
              - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
            type: str
            choices:
              - field-list
              - user-defined
              - none
          delimiter:
            description:
              - Specifies the delimiter string, when C(type) is set to C(field-list).
            type: str
          fields:
            description:
              - Lists the items the server logs, and the order in which the server logs them due to that the order of
                in which items are specified on the list matters. The server displays the items in the log sequentially
                from top down.
              - "The valid elements that can be specified in the list are: action, attack_type, context_name, date_time,
                dest_ip, dest_port, dns_query_name, dns_query_type, route_domain, src_ip, src_port, vlan."
            type: list
            elements: str
          user_string:
            description:
              - Specifies that the format the system uses to log messages is in the form of a user-defined string.
            type: str
  sip_security:
    description:
      - Configure the system to log dropped and malformed malicious SIP requests, global and request failures,
        redirected responses, and server errors for SIP Security.
    type: dict
    suboptions:
      publisher:
        description:
          - Specifies the name of the log publisher used for logging SIP protocol security events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      log_sip_drop:
        description:
          - Enable/Disable logging of dropped SIP requests.
        type: bool
      log_sip_global_failures:
        description:
          - Enable/Disable logging of SIP global failures.
          - The system does not log DNS requests that are dropped due to errors in the way the system
            processes DNS packets.
        type: bool
      log_sip_malformed:
        description:
          - Enable/Disable logging of malformed SIP requests.
        type: bool
      log_sip_redirect_responses:
        description:
          - Enable/Disable logging of SIP redirection responses.
        type: bool
      log_sip_request_failures:
        description:
          - Enable/Disable logging of SIP request failures.
        type: bool
      log_sip_server_errors:
        description:
          - Enable/Disable logging of SIP server errors.
        type: bool
      storage_format:
        description:
          - Configures custom formatting of SIP security log messages.
        type: dict
        suboptions:
          type:
            description:
              - Specifies the format type for log messages.
              - When set to C(none) the system uses default format type to log the messages to a Remote Syslog server.
              - When set to C(field-list) the system uses a set of fields, set in a specific order, to log messages.
              - When set to C(user-defined) the system uses to log messages is in the form of a user-defined string.
              - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
            type: str
            choices:
              - field-list
              - user-defined
              - none
          delimiter:
            description:
              - Specifies the delimiter string, when C(type) is set to C(field-list).
            type: str
          fields:
            description:
              - Lists the items the server logs, and the order in which the server logs them due to that the order of
                in which items are specified on the list matters. The server displays the items in the log sequentially
                from top down.
              - "The valid elements that can be specified in the list are: action, context_name, date_time, dest_ip,
                 dest_port, route_domain, sip_callee, sip_caller, sip_method_type, src_ip, src_port, vlan."
            type: list
            elements: str
          user_string:
            description:
              - Specifies that the format the system uses to log messages is in the form of a user-defined string.
            type: str
  network_security:
    description:
      - Configures the system to log network firewall events.
    type: dict
    suboptions:
      publisher:
        description:
          - Specifies the name of the log publisher used for logging network events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      log_acl_match_accept:
        description:
          - "Enable/Disable logging of packets that match ACL rules configured with action = Accept."
        type: bool
      log_acl_match_drop:
        description:
          - Enable/Disable logging of packets that match ACL rules configured with action = Drop."
        type: bool
      log_acl_match_reject:
        description:
          - Enable/Disable logging of packets that match ACL rules configured with action = Reject."
        type: bool
      log_geo_always:
        description:
          - Enable/Disable logging of Geo IP Location information.
        type: bool
      log_ip_errors:
        description:
          - Enable/Disable logging of IP errors.
        type: bool
      log_tcp_events:
        description:
          - "Enable/Disable logging of TCP events (open and close of TCP sessions)."
        type: bool
      log_tcp_errors:
        description:
          - Enable/Disable logging of TCP errors.
        type: bool
      log_translation_fields:
        description:
          - Enable/Disable logging of translation fields in ACL and TCP events.
        type: bool
      log_acl_to_box_deny:
        description:
          - Enable/Disable logging of any packet that is dropped or denied by management port firewall rules.
          - This option takes effect only when management port firewall rules are configured on the device.
        type: bool
      log_user_always:
        description:
          - "Enable/Disable logging of certain subscriber information
            (e.g. subscriber ID and/or subscriber group) if it is available."
          - This option is in effect only when device has a provisioned and configured PEM module in addition to AFM.
        type: bool
      log_uuid_field:
        description:
          - Enable/Disable logging of UUID of the specific rule that triggered the log message.
        type: bool
      rate_limit_acl_match_accept:
        description:
          - Sets a rate limit for all network firewall log messages with this acl match accept action.
          - If this rate limit is exceeded, log messages of this action type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_acl_match_drop:
        description:
          - Sets a rate limit for all network firewall log messages with this acl match drop action.
          - If this rate limit is exceeded, log messages of this action type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_match_reject:
        description:
          - Sets a rate limit for all network firewall log messages with this acl match reject action.
          - If this rate limit is exceeded, log messages of this action type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_aggregate_rate:
        description:
          - Defines a rate limit for all combined network firewall log messages per second.
            Beyond this rate limit, log messages are not logged.
          - Rate Limits are calculated per-second, per TMM, with each TMM throttling as needed,
            independently of other TMMs.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_ip_errors:
        description:
          - Sets a rate limit for logging of IP error packets.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_tcp_errors:
        description:
          - Sets a rate limit for logging of TCP error packets.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_tcp_events:
        description:
          - Sets a rate limit for logging of TCP events.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      storage_format:
        description:
          - Configures custom formatting of network events log messages.
        type: dict
        suboptions:
          type:
            description:
              - Specifies the format type for log messages.
              - When set to C(none) the system uses default format type to log the messages to a Remote Syslog server.
              - When set to C(field-list) the system uses a set of fields, set in a specific order, to log messages.
              - When set to C(user-defined) the system uses to log messages is in the form of a user-defined string.
              - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
            type: str
            choices:
              - field-list
              - user-defined
              - none
          delimiter:
            description:
              - Specifies the delimiter string, when C(type) is set to C(field-list).
            type: str
          fields:
            description:
              - Lists the items the server logs, and the order in which the server logs them due to that the order of
                in which items are specified on the list matters. The server displays the items in the log sequentially
                from top down.
              - "The valid elements that can be specified in the list are: acl_policy_name, acl_policy_type,
                acl_rule_name, acl_rule_uuid, action, bigip_hostname, context_name, context_type, date_time, dest_fqdn,
                dest_geo, dest_ip, dest_ipint_categories, dest_port, drop_reason, management_ip_address, protocol,
                route_domain, sa_translation_pool, sa_translation_type, source_fqdn, source_ipint_categories,
                source_user, src_geo, src_ip, src_port, translated_dest_ip, translated_dest_port,
                translated_ip_protocol, translated_route_domain, translated_src_ip, translated_src_port,
                translated_vlan, vlan."
            type: list
            elements: str
          user_string:
            description:
              - Specifies that the format the system uses to log messages is in the form of a user-defined string.
            type: str
  nat:
    description:
      - Configures the system to log firewall NAT events.
    type: dict
    suboptions:
      publisher:
        description:
          - Specifies the name of the log publisher used for logging Network Address Translation events.
          - "If the desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
      log_subscriber_id:
        description:
          - Enable or disable logging of the subscriber ID associated with a subscriber IP address.
        type: bool
      lsn_legacy_mode:
        description:
          - Enable or disable use of legacy CGNAT/LSN logging facility instead of the new Firewall NAT logging capability.
          - When set to C(true), the C(start_outbound_session), C(start_inbound_session),
            C(end_inbound_session), C(end_outbound_session), C(quota_exceeded) and C(errors), must not be enabled.
            Specifying C(action) to be either C(enabled) or C(backup-allocation-only) while C(lsn_legacy_mode) is C(true)
            will result in API errors.
        type: bool
      rate_limit_aggregate_rate:
        description:
          - Defines a rate limit for all combined NAT log messages per second. Beyond this rate limit,
            log messages are not logged.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_start_outbound_session:
        description:
          - Sets a rate limit for logging of log entries at the start of the translation event for a NAT client.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_end_outbound_session:
        description:
          - Sets a rate limit for logging of log entries at the end of translation event for a NAT client.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_start_inbound_session:
        description:
          - Sets a rate limit for logging of log entries at the start of the incoming connection event for a
            translated endpoint.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_end_inbound_session:
        description:
          - Sets a rate limit for logging of log entries at the end of the incoming connection event for a
            translated endpoint.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_quota_exceeded:
        description:
          - Sets a rate limit for logging of log entries when a NAT client exceeds allocated resources.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      rate_limit_errors:
        description:
          - Sets a rate limit for logging of events when NAT translation errors occur.
          - If this rate limit is exceeded, log messages of this type are not logged until the threshold drops
            below the specified rate.
          - Valid values are C(0 - 4294967295) messages/sec, or C(indefinite). With values C(4294967295) and
            C(indefinite) being synonymous.
        type: str
      start_outbound_session:
        description:
          - Configuration of log entries generated at the start of the incoming connection event for a translated
            endpoint.
        type: dict
        suboptions:
          action:
            description:
              - When set to C(enabled), sets the system to log entries for the start of the incoming connection event
                for a translated endpoint.
              - When set to C(disabled), disables logging of the start of the incoming connection event for a
                translated endpoint.
              - When set to C(backup-allocation-only), sets the system to generate the associated type of log entries
                only when the translation address for the client is chosen from the backup pool.
            choices:
              - enabled
              - disabled
              - backup-allocation-only
            type: str
          include_dest_addr_port:
            description:
              - Enable or disable logging of destination IP address and port information.
            type: bool
          storage_format:
            description:
              - Configures custom formatting of NAT events log messages.
            type: dict
            suboptions:
              type:
                description:
                  - Specifies the format type for log messages.
                  - When set to C(none), the system uses the default format type to log the messages to a Remote Syslog
                    server.
                  - When set to C(field-list), the system uses a set of fields, set in a specific order, to log messages.
                  - When set to C(user-defined), the system uses a user-defined string to log messages.
                  - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
                type: str
                choices:
                  - field-list
                  - user-defined
                  - none
              delimiter:
                description:
                  - Specifies the delimiter string, when C(type) is set to C(field-list).
                type: str
              fields:
                description:
                  - Lists the items the server logs, and the order in which the server logs them. The order in which items
                    are specified in the list matters. The server displays the items in the log
                    sequentially from top down.
                  - "The valid elements that can be specified in the list are: context_name, dest_ip, dest_port,
                    event_name, protocol, route_domain, src_ip, src_port, sub_id, timestamp, translated_dest_ip,
                    translated_dest_port, translated_route_domain, translated_src_ip, translated_src_port."
                type: list
                elements: str
              user_string:
                description:
                  - Specifies the format the system uses to log messages is in the form of a user-defined string.
                type: str
      end_outbound_session:
        description:
          - Configuration of log entries generated at end of translation event for a NAT client.
        type: dict
        suboptions:
          action:
            description:
              - When set to C(enabled), sets system to log entries for end of translation events for a NAT client.
              - When set to C(disabled), disables logging of end of translation events for a NAT client.
              - When set to C(backup-allocation-only), sets the system to generate the associated type of log entries
                only when the translation address for the client is chosen from the backup pool.
            choices:
              - enabled
              - disabled
              - backup-allocation-only
            type: str
          include_dest_addr_port:
            description:
              - Enable or disable logging of destination IP address and port information.
            type: bool
          storage_format:
            description:
              - Configures the custom formatting of NAT events log messages.
            type: dict
            suboptions:
              type:
                description:
                  - Specifies the format type for log messages.
                  - When set to C(none), the system uses the default format type to log the messages to a Remote Syslog
                    server.
                  - When set to C(field-list), the system uses a set of fields, set in a specific order, to log messages.
                  - When set to C(user-defined), the system uses a user-defined string to log messages.
                  - When set to C(none), the C(fields) and C(user_string) parameters are ignored.
                type: str
                choices:
                  - field-list
                  - user-defined
                  - none
              delimiter:
                description:
                  - Specifies the delimiter string, when C(type) is set to C(field-list).
                type: str
              fields:
                description:
                  - Lists the items the server logs, and the order in which the server logs them. The order
                    in which items are specified in the list matters. The server displays the items in the log
                    sequentially from top down.
                  - "The valid elements that can be specified in the list are: context_name, dest_ip, dest_port,
                    event_name, protocol, route_domain, src_ip, src_port, sub_id, timestamp, translated_dest_ip,
                    translated_dest_port, translated_route_domain, translated_src_ip, translated_src_port."
                type: list
                elements: str
              user_string:
                description:
                  - Specifies the format the system uses to log messages is in the form of a user-defined string.
                type: str
      start_inbound_session:
        description:
          - Configuration of log entries generated at the start of the incoming connection event for a
            translated endpoint.
        type: dict
        suboptions:
          action:
            description:
              - When set to C(enabled), sets the system to log entries for start of the incoming connection event for a
                translated endpoint.
              - When set to C(disabled), disables logging of the start of the incoming connection event for a
                translated endpoint.
              - When set to C(backup-allocation-only), sets the system to generate the associated type of log entries
                only when the translation address for the client is chosen from the backup pool.
            choices:
              - enabled
              - disabled
              - backup-allocation-only
            type: str
          storage_format:
            description:
              - Configures the custom formatting of NAT events log messages.
            type: dict
            suboptions:
              type:
                description:
                  - Specifies the format type for log messages.
                  - When set to C(none), the system uses default format type to log the messages to a Remote Syslog
                    server.
                  - When set to C(field-list), the system uses a set of fields, set in a specific order, to log messages.
                  - When set to C(user-defined), the system uses a user-defined string to log messages.
                  - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
                type: str
                choices:
                  - field-list
                  - user-defined
                  - none
              delimiter:
                description:
                  - Specifies the delimiter string, when C(type) is set to C(field-list).
                type: str
              fields:
                description:
                  - Lists the items the server logs, and the order in which the server logs them. The order
                    in which items are specified in the list matters. The server displays the items in the log
                    sequentially from top down.
                  - "The valid elements that can be specified in the list are: context_name, dest_ip, dest_port,
                    event_name, protocol, route_domain, src_ip, src_port, sub_id, timestamp, translated_dest_ip,
                    translated_dest_port, translated_route_domain, translated_src_ip, translated_src_port."
                type: list
                elements: str
              user_string:
                description:
                  - Specifies the format the system uses to log messages is in the form of a user-defined string.
                type: str
      end_inbound_session:
        description:
          - Configuration of log entries generated at the end of the incoming connection event for a translated endpoint.
        type: dict
        suboptions:
          action:
            description:
              - When set to C(enabled), sets system to log entries for the end of the incoming connection event for a
                translated endpoint.
              - When set to C(disabled), disables logging of the end of the incoming connection event for a translated
                endpoint.
              - When set to C(backup-allocation-only), sets the system to generate the associated type of log entries
                only when the translation address for the client is chosen from the backup pool.
            choices:
              - enabled
              - disabled
              - backup-allocation-only
            type: str
          storage_format:
            description:
              - Configures the custom formatting of NAT events log messages.
            type: dict
            suboptions:
              type:
                description:
                  - Specifies the format type for log messages.
                  - When set to C(none) the system uses default format type to log the messages to a Remote Syslog
                    server.
                  - When set to C(field-list) the system uses a set of fields, set in a specific order, to log messages.
                  - When set to C(user-defined) the system uses a user-defined string to log messages.
                  - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
                type: str
                choices:
                  - field-list
                  - user-defined
                  - none
              delimiter:
                description:
                  - Specifies the delimiter string, when C(type) is set to C(field-list).
                type: str
              fields:
                description:
                  - Lists the items the server logs, and the order in which the server logs them. The order
                    in which items are specified in the list matters. The server displays the items in the log
                    sequentially from top down.
                  - "The valid elements that can be specified in the list are: context_name, dest_ip, dest_port,
                    event_name, protocol, route_domain, src_ip, src_port, sub_id, timestamp, translated_dest_ip,
                    translated_dest_port, translated_route_domain, translated_src_ip, translated_src_port."
                type: list
                elements: str
              user_string:
                description:
                  - Specifies the format the system uses to log messages is in the form of a user-defined string.
                type: str
      quota_exceeded:
        description:
          - Configuration of log entries generated when a NAT client exceeds allocated resources.
        type: dict
        suboptions:
          action:
            description:
              - When set to C(enabled), sets the system to log entries generated when a NAT client exceeds allocated
                resources.
              - When set to C(disabled), disables logging of events when a NAT client exceeds allocated resources.
            choices:
              - enabled
              - disabled
            type: str
          storage_format:
            description:
              - Configures the custom formatting of NAT events log messages.
            type: dict
            suboptions:
              type:
                description:
                  - Specifies the format type for log messages.
                  - When set to C(none) the system uses default format type to log the messages to a Remote Syslog
                    server.
                  - When set to C(field-list), the system uses a set of fields, set in a specific order, to log messages.
                  - When set to C(user-defined) the system uses a user-defined string to log messages.
                  - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
                type: str
                choices:
                  - field-list
                  - user-defined
                  - none
              delimiter:
                description:
                  - Specifies the delimiter string, when C(type) is set to C(field-list).
                type: str
              fields:
                description:
                  - Lists the items the server logs, and the order in which the server logs them. The order
                    in which items are specified in the list matters. The server displays the items in the log
                    sequentially from top down.
                  - "The valid elements that can be specified in the list are: context_name, dest_ip, dest_port,
                    event_name, protocol, route_domain, src_ip, src_port, sub_id, timestamp, translated_dest_ip,
                    translated_dest_port, translated_route_domain, translated_src_ip, translated_src_port."
                type: list
                elements: str
              user_string:
                description:
                  - Specifies the format the system uses to log messages is in the form of a user-defined string.
                type: str
      errors:
        description:
          - Configuration of log entries generated when a NAT translation errors occur.
        type: dict
        suboptions:
          action:
            description:
              - When set to C(enabled), sets the system to log entries generated when a NAT translation errors occur.
              - When set to C(disabled), disables logging of entries generated when a NAT translation errors occur.
            choices:
              - enabled
              - disabled
            type: str
          storage_format:
            description:
              - Configures the custom formatting of NAT events log messages.
            type: dict
            suboptions:
              type:
                description:
                  - Specifies the format type for log messages.
                  - When set to C(none) the system uses default format type to log the messages to a Remote Syslog
                    server.
                  - When set to C(field-list) the system uses a set of fields, set in a specific order, to log messages.
                  - When set to C(user-defined) the system uses a user-defined string to log messages.
                  - When set to C(none) the C(fields) and C(user_string) parameters are ignored.
                type: str
                choices:
                  - field-list
                  - user-defined
                  - none
              delimiter:
                description:
                  - Specifies the delimiter string, when C(type) is set to C(field-list).
                type: str
              fields:
                description:
                  - Lists the items the server logs, and the order in which the server logs them. The order
                    in which items are specified in the list matters. The server displays the items in the log
                    sequentially from top down.
                  - "The valid elements that can be specified in the list are: context_name, dest_ip, dest_port,
                    event_name, protocol, route_domain, src_ip, src_port, sub_id, timestamp, translated_dest_ip,
                    translated_dest_port, translated_route_domain, translated_src_ip, translated_src_port."
                type: list
                elements: str
              user_string:
                description:
                  - Specifies the format the system uses to log messages is in the form of a user-defined string.
                type: str
  protocol_inspection:
    description:
      - Configures system logging of events from the Protocol Inspection engine.
    type: dict
    suboptions:
      log_packet:
        description:
          - Enables/Disable logging of packet payload for Protocol Inspection events.
        type: bool
      publisher:
        description:
          - Specifies the name of the log publisher used for logging of Protocol Inspection events.
          - "If desired log publisher is configured on a different partition to where log profile is created
            a publisher name must be specified in full_path format e.g. /Foo/my-publisher."
        type: str
  packet_filter:
    description:
      - Configures logging of IPv6 Extension Header packet filter rule match events.
    type: dict
    suboptions:
      rate:
        description:
          - Configures a rate limit for all combined IPv6 Extension Header packet filter log messages per second.
          - Beyond this rate limit, log messages are not logged until the threshold drops below the specified rate.
          - Valid value range is C(1 - 1000) messages/sec
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
          - Enables/Disable logging of all events from the Classification engine.
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
      log_alarm: "yes"
      log_browser: "yes"

- name: Modify a security log profile
  bigip_security_log_profile:
    name: "test_log_profile"
    packet_filter:
      rate: 100
    bot_defense:
      log_alarm: "no"

- name: Delete a security log profile
  bigip_security_log_profile:
    name: "test_log_profile"
    state: absent

- name: Create a security log profile with network security
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
      log_alarm: "yes"
      log_browser: "yes"
    network_security:
      publisher: "local-db-publisher"
      log_acl_match_accept: "yes"
      log_acl_match_drop: "yes"
      rate_limit_acl_match_accept: "1000"
      rate_limit_acl_match_drop: "indefinite"
      storage_format:
        type: "field-list"
        delimiter: "-"
        fields:
          - "acl_policy_name"
          - "acl_rule_name"
          - "date_time"
          - "action"
          - "src_ip"

- name: Modify a security log profile sip security
  bigip_security_log_profile:
    name: "test_log_profile"
    packet_filter:
      rate: 100
    sip_security:
      log_sip_drop: "yes"
      log_sip_server_errors: "yes"
      storage_format:
        type: "field-list"
        delimiter: ";"
        fields:
          - "date_time"
          - "dest_ip"
          - "sip_callee"
          - "sip_caller"
'''

RETURN = r'''
auto_discovery:
  description:
    - The log publisher the system uses to log Auto Discovered Service/Server events.
  returned: changed
  type: str
  sample: /Common/foo-publisher
bot_defense:
  description:
    - The system logging of events from the Bot Defense mechanism.
  returned: changed
  type: complex
  contains:
    publisher:
      description:
        - The name of the local log publisher used for Bot Defense log messages.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    send_remote_challenge_failure_messages:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_alarm:
      description:
        - Enable/Disable logging of requests triggering ALARM mitigation action of the Bot Defense logging profile.
      returned: changed
      type: bool
      sample: true
    log_block:
      description:
        - Enable/Disable logging of requests triggering Block mitigation action of the Bot Defense logging profile.
      returned: changed
      type: bool
      sample: true
    log_browser:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_browser_verification_action:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_captcha:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_challenge_failure_request:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_device_id_collection_request:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_honeypot_page:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_mobile_application:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_none:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_rate_limit:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_redirect_to_pool:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_suspicious_browser:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_tcp_reset:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_trusted_bot:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_unknown:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
    log_untrusted_bot:
      description:
        - "TBD"
      returned: changed
      type: bool
      sample: true
classification:
  description:
    - The system logging of events from the Classification engine.
  returned: changed
  type: complex
  contains:
    log_matches:
        description:
          - Enables/Disable logging of all events from the Classification engine.
        returned: changed
        type: bool
        sample: true
    publisher:
      description:
        - The name of the log publisher used for logging of Classification engine events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
description:
  description:
    - Specifies descriptive text that identifies security log profile.
  returned: changed
  type: str
  sample: 'this is a text'
dos_protection:
  description:
    - The log publishers used by the system to log detected DoS attacks.
  returned: changed
  type: complex
  contains:
    application:
      description:
        - The log publisher used for log Application DoS attacks.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    network:
      description:
        - The log publisher used for logging Network DoS events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    dns:
      description:
        - The log publisher used for logging DNS DoS events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    sip:
      description:
        - The log publisher the system uses to log SIP DoS events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
packet_filter:
  description:
    - Configures logging of IPv6 Extension Header packet filter rule match events.
  returned: changed
  type: complex
  contains:
    rate:
      description:
        - The rate limit for all combined IPv6 Extension Header packet filter log messages per second.
      returned: changed
      type: int
      sample: 400
    publisher:
      description:
        - The name of the log publisher used for logging of IPv6 Extension Header Packet Filter rule match events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
protocol_inspection:
  description:
    - Configures logging of events from the Protocol Inspection engine.
  returned: changed
  type: complex
  contains:
    rate:
      description:
        - Enables/Disable logging of packet payload for Protocol Inspection events.
      returned: changed
      type: bool
      sample: true
    publisher:
      description:
        - The name of the log publisher used for logging of Protocol Inspection events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
dns_security:
  description:
    - Configures the system to log dropped, malformed, or rejected requests for DNS Security.
  returned: changed
  type: complex
  contains:
    publisher:
      description:
        - The name of the log publisher used for logging DNS security events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    log_dns_drop:
      description:
        - Enable/Disable logging of dropped DNS requests.
      returned: changed
      type: bool
      sample: true
    log_dns_filtered_drop:
      description:
        - Enable/Disable logging of DNS requests dropped due to DNS query/header-opcode filtering.
      returned: changed
      type: bool
      sample: true
    log_dns_malformed:
      description:
        - Enable/Disable logging of malformed DNS requests.
      returned: changed
      type: bool
      sample: true
    log_dns_malicious:
      description:
        - Enable/Disable logging of malicious DNS requests.
      returned: changed
      type: bool
      sample: true
    log_dns_reject:
      description:
        - Enable/Disable logging of rejected DNS requests.
      returned: changed
      type: bool
      sample: true
    storage_format:
      description:
        - The formatting of DNS security log messages.
      returned: changed
      type: complex
      contains:
        type:
          description:
            - The format type for log messages.
          returned: changed
          type: str
          sample: user-defined
        delimiter:
          description:
            - The delimiter string.
          returned: changed
          type: str
          sample: "-"
        fields:
          description:
            - The items the server logs.
          returned: changed
          type: list
          sample: ['action', 'vlan']
        user_string:
          description:
            - User-defined string.
          returned: changed
          type: str
          sample: "$action"
sip_security:
  description:
    - Configures the system to log dropped and malformed malicious SIP requests, global and request failures,
      redirected responses, and server errors for SIP Security.
  returned: changed
  type: complex
  contains:
    publisher:
      description:
        - The name of the log publisher used for logging SIP protocol security events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    log_sip_drop:
      description:
        - Enable/Disable logging of dropped SIP requests.
      returned: changed
      type: bool
      sample: true
    log_sip_global_failures:
      description:
        - Enable/Disable logging of SIP global failures.
      returned: changed
      type: bool
      sample: true
    log_sip_malformed:
      description:
        - Enable/Disable logging of malformed SIP requests.
      returned: changed
      type: bool
      sample: true
    log_sip_redirect_responses:
      description:
        - Enable/Disable logging of SIP redirection responses.
      returned: changed
      type: bool
      sample: true
    log_sip_request_failures:
      description:
        - Enable/Disable logging of SIP request failures.
      returned: changed
      type: bool
      sample: true
    log_sip_server_errors:
      description:
        - Enable/Disable logging of SIP server errors.
      returned: changed
      type: bool
      sample: true
    storage_format:
      description:
        - The formatting of SIP security log messages.
      returned: changed
      type: complex
      contains:
        type:
          description:
            - The format type for log messages.
          returned: changed
          type: str
          sample: user-defined
        delimiter:
          description:
            - The delimiter string.
          returned: changed
          type: str
          sample: "-"
        fields:
          description:
            - The items the server logs.
          returned: changed
          type: list
          sample: ['action', 'vlan']
        user_string:
          description:
            - User-defined string.
          returned: changed
          type: str
          sample: "$action"
network_security:
  description:
    - Configures the system to log network firewall events.
  returned: changed
  type: complex
  contains:
    publisher:
      description:
        - The name of the log publisher used for logging network events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    log_acl_match_accept:
      description:
        - Enable/Disable logging of packets that match ACL rules action accept.
      returned: changed
      type: bool
      sample: true
    log_acl_match_drop:
      description:
        - Enable/Disable logging of packets that match ACL rules action drop.
      returned: changed
      type: bool
      sample: true
    log_acl_match_reject:
      description:
        - Enable/Disable logging of packets that match ACL rules action reject.
      returned: changed
      type: bool
      sample: true
    log_geo_always:
      description:
        - Enable/Disable logging of Geo IP Location information.
      returned: changed
      type: bool
      sample: true
    log_ip_errors:
      description:
        - Enable/Disable logging of IP errors.
      returned: changed
      type: bool
      sample: true
    log_tcp_events:
      description:
        - Enable/Disable logging of TCP events.
      returned: changed
      type: bool
      sample: true
    log_tcp_errors:
      description:
        - Enable/Disable logging of TCP errors.
      returned: changed
      type: bool
      sample: true
    log_translation_fields:
      description:
        - Enable/Disable logging of translation fields in ACL and TCP events.
      returned: changed
      type: bool
      sample: true
    log_acl_to_box_deny:
      description:
        - nable/Disable logging of any packet that is dropped or denied by management port firewall rules.
      returned: changed
      type: bool
      sample: true
    log_user_always:
      description:
        - Enable/Disable logging of certain subscriber information.
      returned: changed
      type: bool
      sample: true
    log_uuid_field:
      description:
        - Enable/Disable logging of UUID of the specific rule that triggered the log message.
      returned: changed
      type: bool
      sample: true
    rate_limit_acl_match_accept:
      description:
        - The rate limit for all network firewall log messages with this acl match accept action.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_acl_match_drop:
      description:
        - The rate limit for all network firewall log messages with this acl match drop action.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_match_reject:
      description:
        - The rate limit for all network firewall log messages with this acl match reject action.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_aggregate_rate:
      description:
        - The rate limit for all combined network firewall log messages per second.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_ip_errors:
      description:
        - The rate limit for logging of IP error packet.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_tcp_errors:
      description:
        - The rate limit for logging of TCP error packets.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_tcp_events:
      description:
        - The rate limit for logging of TCP events.
      returned: changed
      type: str
      sample: indefinite
    storage_format:
      description:
        - The formatting of network events log messages.
      returned: changed
      type: complex
      contains:
        type:
          description:
            - The format type for log messages.
          returned: changed
          type: str
          sample: user-defined
        delimiter:
          description:
            - The delimiter string.
          returned: changed
          type: str
          sample: "-"
        fields:
          description:
            - The items the server logs.
          returned: changed
          type: list
          sample: ['action', 'vlan']
        user_string:
          description:
            - User-defined string.
          returned: changed
          type: str
          sample: "$action"
nat:
  description:
    - Configures the system to log firewall NAT events.
  returned: changed
  type: complex
  contains:
    publisher:
      description:
        - The name of the log publisher used for logging Network Address Translation events.
      returned: changed
      type: str
      sample: /Common/foo-publisher
    log_subscriber_id:
      description:
        - Enable/Disable logging of the subscriber ID associated with a subscriber IP address.
      returned: changed
      type: bool
      sample: true
    lsn_legacy_mode:
      description:
        - Enable/Disable use of legacy CGNAT/LSN logging facility instead of the new Firewall NAT logging capability.
      returned: changed
      type: bool
      sample: true
    rate_limit_aggregate_rate:
      description:
        - The rate limit for all combined NAT log messages per second.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_start_outbound_session:
      description:
        - The rate limit for logging of log entries at start of the translation event for a NAT client.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_end_outbound_session:
      description:
        - The rate limit for logging of log entries at end of translation event for a NAT client.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_start_inbound_session:
      description:
        - The rate limit for logging of log entries at the start of the incoming connection event for a
          translated endpoint.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_end_inbound_session:
      description:
        - The rate limit for logging of log entries at the end of the incoming connection event for a
          translated endpoint.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_quota_exceeded:
      description:
        - The rate limit for logging of log entries when a NAT client exceeds allocated resources.
      returned: changed
      type: str
      sample: indefinite
    rate_limit_errors:
      description:
        - The rate limit for logging of events when NAT translation errors occur.
      returned: changed
      type: str
      sample: indefinite
    start_outbound_session:
      description:
        - Configuration of log entries generated at the start of the incoming connection event for a
          translated endpoint.
      returned: changed
      type: complex
      contains:
        action:
          description:
            - Configures system to log entries for the start of the incoming connection event for a
              translated endpoint.
          returned: changed
          type: str
          sample: enabled
        include_dest_addr_port:
          description:
            - Enable/Disable logging of destination IP address and port information.
          returned: changed
          type: bool
          sample: true
        storage_format:
          description:
            - The formatting of NAT events log messages.
          returned: changed
          type: complex
          contains:
            type:
              description:
                - The format type for log messages.
              returned: changed
              type: str
              sample: user-defined
            delimiter:
              description:
                - The delimiter string.
              returned: changed
              type: str
              sample: "-"
            fields:
              description:
                - The items the server logs.
              returned: changed
              type: list
              sample: ['dest_ip', 'dest_port']
            user_string:
              description:
                - User-defined string.
              returned: changed
              type: str
              sample: "$dest_ip"
    end_outbound_session:
      description:
        - Configuration of log entries generated at end of translation event for a NAT client.
      returned: changed
      type: complex
      contains:
        action:
          description:
            - Configures system to log entries for the end of translation event for a NAT client.
          returned: changed
          type: str
          sample: enabled
        include_dest_addr_port:
          description:
            - Enable/Disable logging of destination IP address and port information.
          returned: changed
          type: bool
          sample: true
        storage_format:
          description:
            - The formatting of NAT events log messages.
          returned: changed
          type: complex
          contains:
            type:
              description:
                - The format type for log messages.
              returned: changed
              type: str
              sample: user-defined
            delimiter:
              description:
                - The delimiter string.
              returned: changed
              type: str
              sample: "-"
            fields:
              description:
                - The items the server logs.
              returned: changed
              type: list
              sample: ['dest_ip', 'dest_port']
            user_string:
              description:
                - User-defined string.
              returned: changed
              type: str
              sample: "$dest_ip"
    start_inbound_session:
      description:
        - Configuration of log entries generated at the start of the incoming connection event for a
          translated endpoint.
      returned: changed
      type: complex
      contains:
        action:
          description:
            - Configures system to log entries for start of the incoming connection event for a
              translated endpoint.
          returned: changed
          type: str
          sample: enabled
        storage_format:
          description:
            - The formatting of NAT events log messages.
          returned: changed
          type: complex
          contains:
            type:
              description:
                - The format type for log messages.
              returned: changed
              type: str
              sample: user-defined
            delimiter:
              description:
                - The delimiter string.
              returned: changed
              type: str
              sample: "-"
            fields:
              description:
                - The items the server logs.
              returned: changed
              type: list
              sample: ['dest_ip', 'dest_port']
            user_string:
              description:
                - User-defined string.
              returned: changed
              type: str
              sample: "$dest_ip"
    end_inbound_session:
      description:
        - Configuration of log entries generated the end of the incoming connection event for a translated endpoint.
      returned: changed
      type: complex
      contains:
        action:
          description:
            - Configures system to log entries for the end of the incoming connection event for a
              translated endpoint.
          returned: changed
          type: str
          sample: enabled
        storage_format:
          description:
            - The formatting of NAT events log messages.
          returned: changed
          type: complex
          contains:
            type:
              description:
                - The format type for log messages.
              returned: changed
              type: str
              sample: user-defined
            delimiter:
              description:
                - The delimiter string.
              returned: changed
              type: str
              sample: "-"
            fields:
              description:
                - The items the server logs.
              returned: changed
              type: list
              sample: ['dest_ip', 'dest_port']
            user_string:
              description:
                - User-defined string.
              returned: changed
              type: str
              sample: "$dest_ip"
    quota_exceeded:
      description:
        - Configuration of log entries generated when a NAT client exceeds allocated resources.
      returned: changed
      type: complex
      contains:
        action:
          description:
            - Configures system to log entries generated when a NAT client exceeds allocated resources.
          returned: changed
          type: str
          sample: enabled
        storage_format:
          description:
            - The formatting of NAT events log messages.
          returned: changed
          type: complex
          contains:
            type:
              description:
                - The format type for log messages.
              returned: changed
              type: str
              sample: user-defined
            delimiter:
              description:
                - The delimiter string.
              returned: changed
              type: str
              sample: "-"
            fields:
              description:
                - The items the server logs.
              returned: changed
              type: list
              sample: ['dest_ip', 'dest_port']
            user_string:
              description:
                - User-defined string.
              returned: changed
              type: str
              sample: "$dest_ip"
    errors:
      description:
        - Configuration of log entries generated when a NAT translation errors occur.
      returned: changed
      type: complex
      contains:
        action:
          description:
            - Configures system to log entries generated when a NAT translation errors occur.
          returned: changed
          type: str
          sample: enabled
        storage_format:
          description:
            - The formatting of NAT events log messages.
          returned: changed
          type: complex
          contains:
            type:
              description:
                - The format type for log messages.
              returned: changed
              type: str
              sample: user-defined
            delimiter:
              description:
                - The delimiter string.
              returned: changed
              type: str
              sample: "-"
            fields:
              description:
                - The items the server logs.
              returned: changed
              type: list
              sample: ['dest_ip', 'dest_port']
            user_string:
              description:
                - User-defined string.
              returned: changed
              type: str
              sample: "$dest_ip"
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
from ..module_utils.compare import (
    cmp_str_with_none, cmp_simple_list
)


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
        'botDefense',
        'dns_security',
        'sip_security',
        'network_security',
        'nat'
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
        'bot_log_untrusted_bot',
        'dns_sec_publisher',
        'dns_sec_log_dns_drop',
        'dns_sec_log_filter_drop',
        'dns_sec_log_malformed',
        'dns_sec_log_malicious',
        'dns_sec_log_dns_reject',
        'dns_storage_format_type',
        'dns_storage_format_delimiter',
        'dns_storage_format_fields',
        'dns_storage_format_user_string',
        'sip_sec_publisher',
        'sip_sec_log_sip_drop',
        'sip_sec_log_global_fail',
        'sip_sec_log_malformed',
        'sip_sec_log_redirect_response',
        'sip_sec_log_sip_failure',
        'sip_sec_log_sip_server_err',
        'sip_storage_format_type',
        'sip_storage_format_delimiter',
        'sip_storage_format_fields',
        'sip_storage_format_user_string',
        'net_sec_publisher',
        'net_sec_log_acl_match_accept',
        'net_sec_log_acl_match_drop',
        'net_sec_log_acl_match_reject',
        'net_sec_log_geo_always',
        'net_sec_log_ip_errors',
        'net_sec_log_tcp_errors',
        'net_sec_log_tcp_events',
        'net_sec_log_translation_fields',
        'net_sec_log_user_always',
        'net_sec_log_uuid_field',
        'net_sec_rate_limit_acl_match_accept',
        'net_sec_rate_limit_acl_match_drop',
        'net_sec_rate_limit_match_reject',
        'net_sec_rate_limit_aggregate_rate',
        'net_sec_rate_limit_log_acl_to_box_deny',
        'net_sec_rate_limit_ip_errors',
        'net_sec_rate_limit_tcp_errors',
        'net_sec_rate_limit_tcp_events',
        'net_storage_format_type',
        'net_storage_format_delimiter',
        'net_storage_format_fields',
        'net_storage_format_user_string',
        'nat_publisher',
        'nat_rate_limit_aggregate_rate',
        'nat_log_sub_id',
        'nat_lsn_legacy_mode',
        'nat_start_out_action',
        'nat_start_out_incl_dst_addr_port',
        'nat_rate_limit_start_out_sess',
        'nat_start_out_storage_format_type',
        'nat_start_out_storage_format_delimiter',
        'nat_start_out_storage_format_fields',
        'nat_start_out_storage_format_user_string',
        'nat_end_out_action',
        'nat_end_out_incl_dst_addr_port',
        'nat_rate_limit_end_out_sess',
        'nat_end_out_storage_format_type',
        'nat_end_out_storage_format_delimiter',
        'nat_end_out_storage_format_fields',
        'nat_end_out_storage_format_user_string',
        'nat_start_in_action',
        'nat_rate_limit_start_in_sess',
        'nat_start_in_storage_format_type',
        'nat_start_in_storage_format_delimiter',
        'nat_start_in_storage_format_fields',
        'nat_start_in_storage_format_user_string',
        'nat_end_in_action',
        'nat_rate_limit_end_in_sess',
        'nat_end_in_storage_format_type',
        'nat_end_in_storage_format_delimiter',
        'nat_end_in_storage_format_fields',
        'nat_end_in_storage_format_user_string',
        'nat_quota_exceeded_action',
        'nat_rate_limit_quota_exceeded',
        'nat_quota_exceeded_storage_format_type',
        'nat_quota_exceeded_storage_format_delimiter',
        'nat_quota_exceeded_storage_format_fields',
        'nat_quota_exceeded_storage_format_user_string',
        'nat_errors_action',
        'nat_rate_limit_errors',
        'nat_errors_storage_format_type',
        'nat_errors_storage_format_delimiter',
        'nat_errors_storage_format_fields',
        'nat_errors_storage_format_user_string'
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
        'bot_log_untrusted_bot',
        'dns_sec_publisher',
        'dns_sec_log_dns_drop',
        'dns_sec_log_filter_drop',
        'dns_sec_log_malformed',
        'dns_sec_log_malicious',
        'dns_sec_log_dns_reject',
        'dns_storage_format_type',
        'dns_storage_format_delimiter',
        'dns_storage_format_fields',
        'dns_storage_format_user_string',
        'sip_sec_publisher',
        'sip_sec_log_sip_drop',
        'sip_sec_log_global_fail',
        'sip_sec_log_malformed',
        'sip_sec_log_redirect_response',
        'sip_sec_log_sip_failure',
        'sip_sec_log_sip_server_err',
        'sip_storage_format_type',
        'sip_storage_format_delimiter',
        'sip_storage_format_fields',
        'sip_storage_format_user_string',
        'net_sec_publisher',
        'net_sec_log_acl_match_accept',
        'net_sec_log_acl_match_drop',
        'net_sec_log_acl_match_reject',
        'net_sec_log_geo_always',
        'net_sec_log_ip_errors',
        'net_sec_log_tcp_errors',
        'net_sec_log_tcp_events',
        'net_sec_log_translation_fields',
        'net_sec_log_user_always',
        'net_sec_log_uuid_field',
        'net_sec_rate_limit_acl_match_accept',
        'net_sec_rate_limit_acl_match_drop',
        'net_sec_rate_limit_match_reject',
        'net_sec_rate_limit_aggregate_rate',
        'net_sec_rate_limit_log_acl_to_box_deny',
        'net_sec_rate_limit_ip_errors',
        'net_sec_rate_limit_tcp_errors',
        'net_sec_rate_limit_tcp_events',
        'net_storage_format_type',
        'net_storage_format_delimiter',
        'net_storage_format_fields',
        'net_storage_format_user_string',
        'nat_publisher',
        'nat_rate_limit_aggregate_rate',
        'nat_log_sub_id',
        'nat_lsn_legacy_mode',
        'nat_start_out_action',
        'nat_start_out_incl_dst_addr_port',
        'nat_rate_limit_start_out_sess',
        'nat_start_out_storage_format_type',
        'nat_start_out_storage_format_delimiter',
        'nat_start_out_storage_format_fields',
        'nat_start_out_storage_format_user_string',
        'nat_end_out_action',
        'nat_end_out_incl_dst_addr_port',
        'nat_rate_limit_end_out_sess',
        'nat_end_out_storage_format_type',
        'nat_end_out_storage_format_delimiter',
        'nat_end_out_storage_format_fields',
        'nat_end_out_storage_format_user_string',
        'nat_start_in_action',
        'nat_rate_limit_start_in_sess',
        'nat_start_in_storage_format_type',
        'nat_start_in_storage_format_delimiter',
        'nat_start_in_storage_format_fields',
        'nat_start_in_storage_format_user_string',
        'nat_end_in_action',
        'nat_rate_limit_end_in_sess',
        'nat_end_in_storage_format_type',
        'nat_end_in_storage_format_delimiter',
        'nat_end_in_storage_format_fields',
        'nat_end_in_storage_format_user_string',
        'nat_quota_exceeded_action',
        'nat_rate_limit_quota_exceeded',
        'nat_quota_exceeded_storage_format_type',
        'nat_quota_exceeded_storage_format_delimiter',
        'nat_quota_exceeded_storage_format_fields',
        'nat_quota_exceeded_storage_format_user_string',
        'nat_errors_action',
        'nat_rate_limit_errors',
        'nat_errors_storage_format_type',
        'nat_errors_storage_format_delimiter',
        'nat_errors_storage_format_fields',
        'nat_errors_storage_format_user_string'
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
    def dns_sec_publisher(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security'].get('publisher')

    @property
    def dns_sec_log_dns_drop(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['filter'].get('logDnsDrop')

    @property
    def dns_sec_log_filter_drop(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['filter'].get('logDnsFilteredDrop')

    @property
    def dns_sec_log_malformed(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['filter'].get('logDnsMalformed')

    @property
    def dns_sec_log_malicious(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['filter'].get('logDnsMalicious')

    @property
    def dns_sec_log_dns_reject(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['filter'].get('logDnsReject')

    @property
    def dns_storage_format_type(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['format'].get('type')

    @property
    def dns_storage_format_delimiter(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['format'].get('fieldListDelimiter')

    @property
    def dns_storage_format_fields(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['format'].get('fieldList')

    @property
    def dns_storage_format_user_string(self):
        if self._values['dns_security'] is None:
            return None
        return self._values['dns_security']['format'].get('userDefined')

    @property
    def sip_sec_publisher(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security'].get('publisher')

    @property
    def sip_sec_log_sip_drop(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['filter'].get('logSipDrop')

    @property
    def sip_sec_log_global_fail(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['filter'].get('logSipGlobalFailures')

    @property
    def sip_sec_log_malformed(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['filter'].get('logSipMalformed')

    @property
    def sip_sec_log_redirect_response(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['filter'].get('logSipRedirectionResponses')

    @property
    def sip_sec_log_sip_failure(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['filter'].get('logSipRequestFailures')

    @property
    def sip_sec_log_sip_server_err(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['filter'].get('logSipServerErrors')

    @property
    def sip_storage_format_type(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['format'].get('type')

    @property
    def sip_storage_format_delimiter(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['format'].get('fieldListDelimiter')

    @property
    def sip_storage_format_fields(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['format'].get('fieldList')

    @property
    def sip_storage_format_user_string(self):
        if self._values['sip_security'] is None:
            return None
        return self._values['sip_security']['format'].get('userDefined')

    @property
    def net_sec_publisher(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security'].get('publisher')

    @property
    def net_sec_log_acl_match_accept(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logAclMatchAccept')

    @property
    def net_sec_log_acl_match_drop(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logAclMatchDrop')

    @property
    def net_sec_log_acl_match_reject(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logAclMatchReject')

    @property
    def net_sec_log_geo_always(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logGeoAlways')

    @property
    def net_sec_log_ip_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logIpErrors')

    @property
    def net_sec_log_tcp_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logTcpErrors')

    @property
    def net_sec_log_tcp_events(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logTcpEvents')

    @property
    def net_sec_log_translation_fields(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logTranslationFields')

    @property
    def net_sec_log_user_always(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logUserAlways')

    @property
    def net_sec_log_uuid_field(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['filter'].get('logUuidField')

    @property
    def net_sec_rate_limit_acl_match_accept(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('aclMatchAccept')

    @property
    def net_sec_rate_limit_acl_match_drop(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('aclMatchDrop')

    @property
    def net_sec_rate_limit_match_reject(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('aclMatchReject')

    @property
    def net_sec_rate_limit_aggregate_rate(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('aggregateRate')

    @property
    def net_sec_rate_limit_ip_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('ipErrors')

    @property
    def net_sec_rate_limit_log_acl_to_box_deny(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('logAclToBoxDeny')

    @property
    def net_sec_rate_limit_tcp_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('tcpErrors')

    @property
    def net_sec_rate_limit_tcp_events(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['rateLimit'].get('tcpEvents')

    @property
    def net_storage_format_type(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['format'].get('type')

    @property
    def net_storage_format_delimiter(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['format'].get('fieldListDelimiter')

    @property
    def net_storage_format_fields(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['format'].get('fieldList')

    @property
    def net_storage_format_user_string(self):
        if self._values['network_security'] is None:
            return None
        return self._values['network_security']['format'].get('userDefined')

    @property
    def nat_publisher(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('logPublisher')

    @property
    def nat_rate_limit_aggregate_rate(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('aggregateRate')

    @property
    def nat_log_sub_id(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('logSubscriberId')

    @property
    def nat_lsn_legacy_mode(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('lsnLegacyMode')

    @property
    def nat_start_out_action(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['startOutboundSession'].get('action')

    @property
    def nat_start_out_incl_dst_addr_port(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['startOutboundSession'].get('elements')

    @property
    def nat_rate_limit_start_out_sess(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('startOutboundSession')

    @property
    def nat_start_out_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startOutboundSession'].get('type')

    @property
    def nat_start_out_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startOutboundSession'].get('fieldListDelimiter')

    @property
    def nat_start_out_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startOutboundSession'].get('fieldList')

    @property
    def nat_start_out_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startOutboundSession'].get('userDefined')

    @property
    def nat_end_out_action(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['endOutboundSession'].get('action')

    @property
    def nat_end_out_incl_dst_addr_port(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['endOutboundSession'].get('elements')

    @property
    def nat_rate_limit_end_out_sess(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('endOutboundSession')

    @property
    def nat_end_out_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endOutboundSession'].get('type')

    @property
    def nat_end_out_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endOutboundSession'].get('fieldListDelimiter')

    @property
    def nat_end_out_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endOutboundSession'].get('fieldList')

    @property
    def nat_end_out_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endOutboundSession'].get('userDefined')

    @property
    def nat_start_in_action(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('startInboundSession')

    @property
    def nat_rate_limit_start_in_sess(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('startInboundSession')

    @property
    def nat_start_in_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startInboundSession'].get('type')

    @property
    def nat_start_in_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startInboundSession'].get('fieldListDelimiter')

    @property
    def nat_start_in_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startInboundSession'].get('fieldList')

    @property
    def nat_start_in_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['startInboundSession'].get('userDefined')

    @property
    def nat_end_in_action(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('endInboundSession')

    @property
    def nat_rate_limit_end_in_sess(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('endInboundSession')

    @property
    def nat_end_in_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endInboundSession'].get('type')

    @property
    def nat_end_in_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endInboundSession'].get('fieldListDelimiter')

    @property
    def nat_end_in_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endInboundSession'].get('fieldList')

    @property
    def nat_end_in_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['endInboundSession'].get('userDefined')

    @property
    def nat_quota_exceeded_action(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('quotaExceeded')

    @property
    def nat_rate_limit_quota_exceeded(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('quotaExceeded')

    @property
    def nat_quota_exceeded_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['quotaExceeded'].get('type')

    @property
    def nat_quota_exceeded_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['quotaExceeded'].get('fieldListDelimiter')

    @property
    def nat_quota_exceeded_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['quotaExceeded'].get('fieldList')

    @property
    def nat_quota_exceeded_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['quotaExceeded'].get('userDefined')

    @property
    def nat_errors_action(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat'].get('errors')

    @property
    def nat_rate_limit_errors(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['rateLimit'].get('errors')

    @property
    def nat_errors_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['errors'].get('type')

    @property
    def nat_errors_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['errors'].get('fieldListDelimiter')

    @property
    def nat_errors_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['errors'].get('fieldList')

    @property
    def nat_errors_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        return self._values['nat']['format']['errors'].get('userDefined')

    @property
    def bot_defense_exists(self):
        if self._values['bot_defense'] is None:
            return False
        return True

    @property
    def dns_sec_exists(self):
        if self._values['dns_security'] is None:
            return False
        return True

    @property
    def sip_sec_exists(self):
        if self._values['sip_security'] is None:
            return False
        return True

    @property
    def net_sec_exists(self):
        if self._values['network_security'] is None:
            return False
        return True


class ModuleParameters(Parameters):
    valid_nat_fields = {'context_name', 'dest_ip', 'dest_port', 'event_name', 'protocol', 'route_domain', 'src_ip',
                        'src_port', 'sub_id', 'timestamp', 'translated_dest_ip', 'translated_dest_port',
                        'translated_route_domain', 'translated_src_ip', 'translated_src_port'}

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

    @staticmethod
    def _handle_rate_limit(item, name):
        if item is None:
            return None
        if item == 'indefinite':
            return 4294967295
        try:
            if 0 <= int(item) <= 4294967295:
                return int(item)
        except ValueError:
            raise F5ModuleError(
                f"Invalid value for {name} must be in range 0 - 4294967295 or 'indefinite', got {item}."
            )
        raise F5ModuleError(
            f"Value out of range: {item}, valid {name} must be in range 0 - 4294967295 or 'indefinite'."
        )

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
        return self._handle_booleans(self._values['bot_defense'].get('log_alarm'))

    @property
    def bot_log_block(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_block'))

    @property
    def bot_log_browser(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_browser'))

    @property
    def bot_log_browser_verify(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_browser_verification_action'))

    @property
    def bot_log_captcha(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_captcha'))

    @property
    def bot_log_challenge_failure(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_challenge_failure_request'))

    @property
    def bot_log_deviceid_coll_req(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_device_id_collection_request'))

    @property
    def bot_log_honey_pot(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_honeypot_page'))

    @property
    def bot_log_mobile_app(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_mobile_application'))

    @property
    def bot_log_none(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_none'))

    @property
    def bot_log_rate_limit(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_rate_limit'))

    @property
    def bot_log_redirect_to_pool(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_redirect_to_pool'))

    @property
    def bot_log_suspect_browser(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_suspicious_browser'))

    @property
    def bot_log_tcp_reset(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_tcp_reset'))

    @property
    def bot_log_trusted_bot(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_trusted_bot'))

    @property
    def bot_log_unknown(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_unknown'))

    @property
    def bot_log_untrusted_bot(self):
        if self._values['bot_defense'] is None:
            return None
        return self._handle_booleans(self._values['bot_defense'].get('log_untrusted_bot'))

    @property
    def dns_sec_publisher(self):
        if self._values['dns_security'] is None:
            return None
        return self._handle_publishers(self._values['dns_security'].get('publisher'))

    @property
    def dns_sec_log_dns_drop(self):
        if self._values['dns_security'] is None:
            return None
        return self._handle_booleans(self._values['dns_security'].get('log_dns_drop'))

    @property
    def dns_sec_log_filter_drop(self):
        if self._values['dns_security'] is None:
            return None
        return self._handle_booleans(self._values['dns_security'].get('log_dns_filtered_drop'))

    @property
    def dns_sec_log_malformed(self):
        if self._values['dns_security'] is None:
            return None
        return self._handle_booleans(self._values['dns_security'].get('log_dns_malformed'))

    @property
    def dns_sec_log_malicious(self):
        if self._values['dns_security'] is None:
            return None
        return self._handle_booleans(self._values['dns_security'].get('log_dns_malicious'))

    @property
    def dns_sec_log_dns_reject(self):
        if self._values['dns_security'] is None:
            return None
        return self._handle_booleans(self._values['dns_security'].get('log_dns_reject'))

    @property
    def dns_storage_format_type(self):
        if self._values['dns_security'] is None:
            return None
        if self._values['dns_security'].get('storage_format'):
            return self._values['dns_security']['storage_format'].get('type')

    @property
    def dns_storage_format_delimiter(self):
        if self._values['dns_security'] is None:
            return None
        if self._values['dns_security'].get('storage_format'):
            return self._values['dns_security']['storage_format'].get('delimiter')

    @property
    def dns_storage_format_fields(self):
        if self._values['dns_security'] is None:
            return None
        if self.dns_storage_format_type == 'none':
            return None
        if self._values['dns_security'].get('storage_format'):
            fields = self._values['dns_security']['storage_format'].get('fields')
            if fields:
                valid = {
                    'action', 'attack_type', 'context_name', 'date_time', 'dest_ip', 'dest_port', 'dns_query_name',
                    'dns_query_type', 'route_domain', 'src_ip', 'src_port', 'vlan'
                }
                if not set(fields).issubset(valid):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {valid}")
                return fields

    @property
    def dns_storage_format_user_string(self):
        if self._values['dns_security'] is None:
            return None
        if self.dns_storage_format_type == 'none':
            return None
        if self._values['dns_security'].get('storage_format'):
            return self._values['dns_security']['storage_format'].get('user_string')

    @property
    def sip_sec_publisher(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_publishers(self._values['sip_security'].get('publisher'))

    @property
    def sip_sec_log_sip_drop(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_booleans(self._values['sip_security'].get('log_sip_drop'))

    @property
    def sip_sec_log_global_fail(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_booleans(self._values['sip_security'].get('log_sip_global_failures'))

    @property
    def sip_sec_log_malformed(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_booleans(self._values['sip_security'].get('log_sip_malformed'))

    @property
    def sip_sec_log_redirect_response(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_booleans(self._values['sip_security'].get('log_sip_redirect_responses'))

    @property
    def sip_sec_log_sip_failure(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_booleans(self._values['sip_security'].get('log_sip_request_failures'))

    @property
    def sip_sec_log_sip_server_err(self):
        if self._values['sip_security'] is None:
            return None
        return self._handle_booleans(self._values['sip_security'].get('log_sip_server_errors'))

    @property
    def sip_storage_format_type(self):
        if self._values['sip_security'] is None:
            return None
        if self._values['sip_security'].get('storage_format'):
            return self._values['sip_security']['storage_format'].get('type')

    @property
    def sip_storage_format_delimiter(self):
        if self._values['sip_security'] is None:
            return None
        if self._values['sip_security'].get('storage_format'):
            return self._values['sip_security']['storage_format'].get('delimiter')

    @property
    def sip_storage_format_fields(self):
        if self._values['sip_security'] is None:
            return None
        if self.sip_storage_format_type == 'none':
            return None
        if self._values['sip_security'].get('storage_format'):
            fields = self._values['sip_security']['storage_format'].get('fields')
            if fields:
                valid = {'action', 'context_name', 'date_time', 'dest_ip', 'dest_port', 'route_domain', 'sip_callee',
                         'sip_caller', 'sip_method_type', 'src_ip', 'src_port', 'vlan'
                         }
                if not set(fields).issubset(valid):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {valid}")
                return fields

    @property
    def sip_storage_format_user_string(self):
        if self._values['sip_security'] is None:
            return None
        if self.sip_storage_format_type == 'none':
            return None
        if self._values['sip_security'].get('storage_format'):
            return self._values['sip_security']['storage_format'].get('user_string')

    @property
    def net_sec_publisher(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_publishers(self._values['network_security'].get('publisher'))

    @property
    def net_sec_log_acl_match_accept(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_acl_match_accept'))

    @property
    def net_sec_log_acl_match_drop(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_acl_match_drop'))

    @property
    def net_sec_log_acl_match_reject(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_acl_match_reject'))

    @property
    def net_sec_rate_limit_log_acl_to_box_deny(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_acl_to_box_deny'))

    @property
    def net_sec_log_geo_always(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_geo_always'))

    @property
    def net_sec_log_ip_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_ip_errors'))

    @property
    def net_sec_log_tcp_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_tcp_errors'))

    @property
    def net_sec_log_tcp_events(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_tcp_events'))

    @property
    def net_sec_log_translation_fields(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_translation_fields'))

    @property
    def net_sec_log_user_always(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_user_always'))

    @property
    def net_sec_log_uuid_field(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_booleans(self._values['network_security'].get('log_uuid_field'))

    @property
    def net_sec_rate_limit_acl_match_accept(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_acl_match_accept'), 'rate_limit_acl_match_accept'
        )

    @property
    def net_sec_rate_limit_acl_match_drop(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_acl_match_drop'), 'rate_limit_acl_match_drop'
        )

    @property
    def net_sec_rate_limit_match_reject(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_match_reject'), 'rate_limit_match_reject'
        )

    @property
    def net_sec_rate_limit_aggregate_rate(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_aggregate_rate'), 'rate_limit_aggregate_rate'
        )

    @property
    def net_sec_rate_limit_ip_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_ip_errors'), 'rate_limit_ip_errors'
        )

    @property
    def net_sec_rate_limit_tcp_errors(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_tcp_errors'), 'rate_limit_tcp_errors'
        )

    @property
    def net_sec_rate_limit_tcp_events(self):
        if self._values['network_security'] is None:
            return None
        return self._handle_rate_limit(
            self._values['network_security'].get('rate_limit_tcp_events'), 'rate_limit_tcp_events'
        )

    @property
    def net_storage_format_type(self):
        if self._values['network_security'] is None:
            return None
        if self._values['network_security'].get('storage_format'):
            return self._values['network_security']['storage_format'].get('type')

    @property
    def net_storage_format_delimiter(self):
        if self._values['network_security'] is None:
            return None
        if self._values['network_security'].get('storage_format'):
            return self._values['network_security']['storage_format'].get('delimiter')

    @property
    def net_storage_format_fields(self):
        if self._values['network_security'] is None:
            return None
        if self.net_storage_format_type == 'none':
            return None
        if self._values['network_security'].get('storage_format'):
            fields = self._values['network_security']['storage_format'].get('fields')
            if fields:
                valid = {
                    'acl_policy_name', 'acl_policy_type', 'acl_rule_name', 'acl_rule_uuid', 'action', 'bigip_hostname',
                    'context_name', 'context_type', 'date_time', 'dest_fqdn', 'dest_geo', 'dest_ip',
                    'dest_ipint_categories', 'dest_port', 'drop_reason', 'management_ip_address', 'protocol',
                    'route_domain', 'sa_translation_pool', 'sa_translation_type', 'source_fqdn',
                    'source_ipint_categories', 'source_user', 'src_geo', 'src_ip', 'src_port', 'translated_dest_ip',
                    'translated_dest_port', 'translated_ip_protocol', 'translated_route_domain', 'translated_src_ip',
                    'translated_src_port', 'translated_vlan', 'vlan'
                }
                if not set(fields).issubset(valid):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {valid}")
                return fields

    @property
    def net_storage_format_user_string(self):
        if self._values['network_security'] is None:
            return None
        if self.net_storage_format_type == 'none':
            return None
        if self._values['network_security'].get('storage_format'):
            return self._values['network_security']['storage_format'].get('user_string')

    @property
    def nat_publisher(self):
        if self._values['nat'] is None:
            return None
        return self._handle_publishers(self._values['nat'].get('publisher'))

    @property
    def nat_rate_limit_aggregate_rate(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_aggregate_rate'), 'rate_limit_aggregate_rate'
        )

    @property
    def nat_log_sub_id(self):
        if self._values['nat'] is None:
            return None
        return self._handle_booleans(self._values['nat'].get('log_subscriber_id'))

    @property
    def nat_lsn_legacy_mode(self):
        if self._values['nat'] is None:
            return None
        return self._handle_booleans(self._values['nat'].get('lsn_legacy_mode'))

    @property
    def nat_start_out_action(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('start_outbound_session'):
            return self._values['nat']['start_outbound_session'].get('action')

    @property
    def nat_start_out_incl_dst_addr_port(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('start_outbound_session'):
            result = flatten_boolean(self._values['nat']['start_outbound_session'].get('include_dest_addr_port'))
            if result == 'yes':
                return ['destination']
            if result == 'no':
                return []

    @property
    def nat_rate_limit_start_out_sess(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_start_outbound_session'), 'rate_limit_start_outbound_session'
        )

    @property
    def nat_start_out_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_outbound_session'):
            return None
        if self._values['nat']['start_outbound_session'].get('storage_format'):
            return self._values['nat']['start_outbound_session']['storage_format'].get('type')

    @property
    def nat_start_out_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_outbound_session'):
            return None
        if self._values['nat']['start_outbound_session'].get('storage_format'):
            return self._values['nat']['start_outbound_session']['storage_format'].get('delimiter')

    @property
    def nat_start_out_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_outbound_session'):
            return None
        if self.nat_start_out_storage_format_type == 'none':
            return None
        if self._values['nat']['start_outbound_session'].get('storage_format'):
            fields = self._values['nat']['start_outbound_session']['storage_format'].get('fields')
            if fields:
                if not set(fields).issubset(self.valid_nat_fields):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {self.valid_nat_fields}")
                return fields

    @property
    def nat_start_out_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_outbound_session'):
            return None
        if self.nat_start_out_storage_format_type == 'none':
            return None
        if self._values['nat']['start_outbound_session'].get('storage_format'):
            return self._values['nat']['start_outbound_session']['storage_format'].get('user_string')

    @property
    def nat_end_out_action(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('end_outbound_session'):
            return self._values['nat']['end_outbound_session'].get('action')

    @property
    def nat_end_out_incl_dst_addr_port(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('end_outbound_session'):
            result = flatten_boolean(self._values['nat']['end_outbound_session'].get('include_dest_addr_port'))
            if result == 'yes':
                return ['destination']
            if result == 'no':
                return []

    @property
    def nat_rate_limit_end_out_sess(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_end_outbound_session'), 'rate_limit_end_outbound_session'
        )

    @property
    def nat_end_out_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_outbound_session'):
            return None
        if self._values['nat']['end_outbound_session'].get('storage_format'):
            return self._values['nat']['end_outbound_session']['storage_format'].get('type')

    @property
    def nat_end_out_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_outbound_session'):
            return None
        if self._values['nat']['end_outbound_session'].get('storage_format'):
            return self._values['nat']['end_outbound_session']['storage_format'].get('delimiter')

    @property
    def nat_end_out_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_outbound_session'):
            return None
        if self.nat_end_out_storage_format_type == 'none':
            return None
        if self._values['nat']['end_outbound_session'].get('storage_format'):
            fields = self._values['nat']['end_outbound_session']['storage_format'].get('fields')
            if fields:
                if not set(fields).issubset(self.valid_nat_fields):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {self.valid_nat_fields}")
                return fields

    @property
    def nat_end_out_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_outbound_session'):
            return None
        if self.nat_end_out_storage_format_type == 'none':
            return None
        if self._values['nat']['end_outbound_session'].get('storage_format'):
            return self._values['nat']['end_outbound_session']['storage_format'].get('user_string')

    @property
    def nat_start_in_action(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('start_inbound_session'):
            return self._values['nat']['start_inbound_session'].get('action')

    @property
    def nat_rate_limit_start_in_sess(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_start_inbound_session'), 'rate_limit_start_inbound_session'
        )

    @property
    def nat_start_in_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_inbound_session'):
            return None
        if self._values['nat']['start_inbound_session'].get('storage_format'):
            return self._values['nat']['start_inbound_session']['storage_format'].get('type')

    @property
    def nat_start_in_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_inbound_session'):
            return None
        if self._values['nat']['start_inbound_session'].get('storage_format'):
            return self._values['nat']['start_inbound_session']['storage_format'].get('delimiter')

    @property
    def nat_start_in_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_inbound_session'):
            return None
        if self.nat_start_in_storage_format_type == 'none':
            return None
        if self._values['nat']['start_inbound_session'].get('storage_format'):
            fields = self._values['nat']['start_inbound_session']['storage_format'].get('fields')
            if fields:
                if not set(fields).issubset(self.valid_nat_fields):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {self.valid_nat_fields}")
                return fields

    @property
    def nat_start_in_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('start_inbound_session'):
            return None
        if self.nat_start_in_storage_format_type == 'none':
            return None
        if self._values['nat']['start_inbound_session'].get('storage_format'):
            return self._values['nat']['start_inbound_session']['storage_format'].get('user_string')

    @property
    def nat_end_in_action(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('end_inbound_session'):
            return self._values['nat']['end_inbound_session'].get('action')

    @property
    def nat_rate_limit_end_in_sess(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_end_inbound_session'), 'rate_limit_end_inbound_session'
        )

    @property
    def nat_end_in_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_inbound_session'):
            return None
        if self._values['nat']['end_inbound_session'].get('storage_format'):
            return self._values['nat']['end_inbound_session']['storage_format'].get('type')

    @property
    def nat_end_in_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_inbound_session'):
            return None
        if self._values['nat']['end_inbound_session'].get('storage_format'):
            return self._values['nat']['end_inbound_session']['storage_format'].get('delimiter')

    @property
    def nat_end_in_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_inbound_session'):
            return None
        if self.nat_end_in_storage_format_type == 'none':
            return None
        if self._values['nat']['end_inbound_session'].get('storage_format'):
            fields = self._values['nat']['end_inbound_session']['storage_format'].get('fields')
            if fields:
                if not set(fields).issubset(self.valid_nat_fields):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {self.valid_nat_fields}")
                return fields

    @property
    def nat_end_in_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('end_inbound_session'):
            return None
        if self.nat_end_in_storage_format_type == 'none':
            return None
        if self._values['nat']['end_inbound_session'].get('storage_format'):
            return self._values['nat']['end_inbound_session']['storage_format'].get('user_string')

    @property
    def nat_quota_exceeded_action(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('quota_exceeded'):
            return self._values['nat']['quota_exceeded'].get('action')

    @property
    def nat_rate_limit_quota_exceeded(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_quota_exceeded'), 'rate_limit_quota_exceeded'
        )

    @property
    def nat_quota_exceeded_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('quota_exceeded'):
            return None
        if self._values['nat']['quota_exceeded'].get('storage_format'):
            return self._values['nat']['quota_exceeded']['storage_format'].get('type')

    @property
    def nat_quota_exceeded_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('quota_exceeded'):
            return None
        if self._values['nat']['quota_exceeded'].get('storage_format'):
            return self._values['nat']['quota_exceeded']['storage_format'].get('delimiter')

    @property
    def nat_quota_exceeded_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('quota_exceeded'):
            return None
        if self.nat_quota_exceeded_storage_format_type == 'none':
            return None
        if self._values['nat']['quota_exceeded'].get('storage_format'):
            fields = self._values['nat']['quota_exceeded']['storage_format'].get('fields')
            if fields:
                if not set(fields).issubset(self.valid_nat_fields):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {self.valid_nat_fields}")
                return fields

    @property
    def nat_quota_exceeded_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('quota_exceeded'):
            return None
        if self.nat_quota_exceeded_storage_format_type == 'none':
            return None
        if self._values['nat']['quota_exceeded'].get('storage_format'):
            return self._values['nat']['quota_exceeded']['storage_format'].get('user_string')

    @property
    def nat_errors_action(self):
        if self._values['nat'] is None:
            return None
        if self._values['nat'].get('errors'):
            return self._values['nat']['errors'].get('action')

    @property
    def nat_rate_limit_errors(self):
        if self._values['nat'] is None:
            return None
        return self._handle_rate_limit(
            self._values['nat'].get('rate_limit_errors'), 'rate_limit_errors'
        )

    @property
    def nat_errors_storage_format_type(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('errors'):
            return None
        if self._values['nat']['errors'].get('storage_format'):
            return self._values['nat']['errors']['storage_format'].get('type')

    @property
    def nat_errors_storage_format_delimiter(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('errors'):
            return None
        if self._values['nat']['errors'].get('storage_format'):
            return self._values['nat']['errors']['storage_format'].get('delimiter')

    @property
    def nat_errors_storage_format_fields(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('errors'):
            return None
        if self.nat_errors_storage_format_type == 'none':
            return None
        if self._values['nat']['errors'].get('storage_format'):
            fields = self._values['nat']['errors']['storage_format'].get('fields')
            if fields:
                if not set(fields).issubset(self.valid_nat_fields):
                    raise F5ModuleError(f"Invalid fields value, list item must be one of: {self.valid_nat_fields}")
                return fields

    @property
    def nat_errors_storage_format_user_string(self):
        if self._values['nat'] is None:
            return None
        if not self._values['nat'].get('errors'):
            return None
        if self.nat_errors_storage_format_type == 'none':
            return None
        if self._values['nat']['errors'].get('storage_format'):
            return self._values['nat']['errors']['storage_format'].get('user_string')


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

    def _finalize_parameter(self, item):
        if item:
            result = self._filter_params(item)
            if result:
                return result


class UsableChanges(Changes):
    @property
    def auto_discovery(self):
        if self._values['auto_discovery'] is None:
            return None
        return self._finalize_parameter(dict(logPublisher=self._values['auto_discovery']))

    @property
    def classification(self):
        return self._finalize_parameter(dict(logAllClassificationMatches=self._values['classification_log'],
                                             logPublisher=self._values['classification_pub']))

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
        return self._finalize_parameter(dict(logPacket=self._values['proto_inspect_log'],
                                             logPublisher=self._values['proto_inspect_pub']))

    @property
    def packet_filter(self):
        return self._finalize_parameter(dict(aggregateRate=self._values['packet_filter_rate'],
                                             logPublisher=self._values['packet_filter_pub']))

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

    @property
    def dns_security(self):
        tmp_filter = self._filter_params(dict(
            logDnsDrop=self._values['dns_sec_log_dns_drop'],
            logDnsFilteredDrop=self._values['dns_sec_log_filter_drop'],
            logDnsMalformed=self._values['dns_sec_log_malformed'],
            logDnsMalicious=self._values['dns_sec_log_malicious'],
            logDnsReject=self._values['dns_sec_log_dns_reject']
        ))
        tmp_format = self._filter_params(dict(
            fieldListDelimiter=self._values['dns_storage_format_delimiter'],
            type=self._values['dns_storage_format_type'],
            fieldList=self._values['dns_storage_format_fields'],
            userDefined=self._values['dns_storage_format_user_string']
        ))
        result = self._filter_params(dict(publisher=self._values['dns_sec_publisher']))

        if tmp_filter:
            result['filter'] = tmp_filter
        if tmp_format:
            result['format'] = tmp_format
        if result:
            return result

    @property
    def sip_security(self):
        tmp_filter = self._filter_params(dict(
            logSipDrop=self._values['sip_sec_log_sip_drop'],
            logSipGlobalFailures=self._values['sip_sec_log_global_fail'],
            logSipMalformed=self._values['sip_sec_log_malformed'],
            logSipRedirectionResponses=self._values['sip_sec_log_redirect_response'],
            logSipRequestFailures=self._values['sip_sec_log_sip_failure'],
            logSipServerErrors=self._values['sip_sec_log_sip_server_err']
        ))
        tmp_format = self._filter_params(dict(
            fieldListDelimiter=self._values['sip_storage_format_delimiter'],
            type=self._values['sip_storage_format_type'],
            fieldList=self._values['sip_storage_format_fields'],
            userDefined=self._values['sip_storage_format_user_string']
        ))
        result = self._filter_params(dict(publisher=self._values['sip_sec_publisher']))

        if tmp_filter:
            result['filter'] = tmp_filter
        if tmp_format:
            result['format'] = tmp_format
        if result:
            return result

    @property
    def network_security(self):
        tmp_filter = self._filter_params(dict(
            logAclMatchAccept=self._values['net_sec_log_acl_match_accept'],
            logAclMatchDrop=self._values['net_sec_log_acl_match_drop'],
            logAclMatchReject=self._values['net_sec_log_acl_match_reject'],
            logGeoAlways=self._values['net_sec_log_geo_always'],
            logAclToBoxDeny=self._values['net_sec_rate_limit_log_acl_to_box_deny'],
            logIpErrors=self._values['net_sec_log_ip_errors'],
            logTcpErrors=self._values['net_sec_log_tcp_errors'],
            logTcpEvents=self._values['net_sec_log_tcp_events'],
            logTranslationFields=self._values['net_sec_log_translation_fields'],
            logUserAlways=self._values['net_sec_log_user_always'],
            logUuidField=self._values['net_sec_log_uuid_field']
        ))
        tmp_rate = self._filter_params(dict(
            aclMatchAccept=self._values['net_sec_rate_limit_acl_match_accept'],
            aclMatchDrop=self._values['net_sec_rate_limit_acl_match_drop'],
            aclMatchReject=self._values['net_sec_rate_limit_match_reject'],
            aggregateRate=self._values['net_sec_rate_limit_aggregate_rate'],
            ipErrors=self._values['net_sec_rate_limit_ip_errors'],
            tcpErrors=self._values['net_sec_rate_limit_tcp_errors'],
            tcpEvents=self._values['net_sec_rate_limit_tcp_events'],
        ))
        tmp_format = self._filter_params(dict(
            fieldListDelimiter=self._values['net_storage_format_delimiter'],
            type=self._values['net_storage_format_type'],
            fieldList=self._values['net_storage_format_fields'],
            userDefined=self._values['net_storage_format_user_string']
        ))

        result = self._filter_params(dict(publisher=self._values['net_sec_publisher']))

        if tmp_filter:
            result['filter'] = tmp_filter
        if tmp_format:
            result['format'] = tmp_format
        if tmp_rate:
            result['rateLimit'] = tmp_rate
        if result:
            return result

    @property
    def nat(self):
        tmp_rate = self._finalize_parameter(dict(
            aggregateRate=self._values['nat_rate_limit_aggregate_rate'],
            endInboundSession=self._values['nat_rate_limit_end_in_sess'],
            endOutboundSession=self._values['nat_rate_limit_end_out_sess'],
            errors=self._values['nat_rate_limit_errors'],
            quotaExceeded=self._values['nat_rate_limit_quota_exceeded'],
            startInboundSession=self._values['nat_rate_limit_start_in_sess'],
            startOutboundSession=self._values['nat_rate_limit_start_out_sess']
        ))

        tmp_format = self._finalize_parameter(dict(
            startOutboundSession=self._finalize_parameter(dict(
                fieldListDelimiter=self._values['nat_start_out_storage_format_delimiter'],
                type=self._values['nat_start_out_storage_format_type'],
                fieldList=self._values['nat_start_out_storage_format_fields'],
                userDefined=self._values['nat_start_out_storage_format_user_string']
            )),
            endOutboundSession=self._finalize_parameter(dict(
                fieldListDelimiter=self._values['nat_end_out_storage_format_delimiter'],
                type=self._values['nat_end_out_storage_format_type'],
                fieldList=self._values['nat_end_out_storage_format_fields'],
                userDefined=self._values['nat_end_out_storage_format_user_string']
            )),
            startInboundSession=self._finalize_parameter(dict(
                fieldListDelimiter=self._values['nat_start_in_storage_format_delimiter'],
                type=self._values['nat_start_in_storage_format_type'],
                fieldList=self._values['nat_start_in_storage_format_fields'],
                userDefined=self._values['nat_start_in_storage_format_user_string']
            )),
            endInboundSession=self._finalize_parameter(dict(
                fieldListDelimiter=self._values['nat_end_in_storage_format_delimiter'],
                type=self._values['nat_end_in_storage_format_type'],
                fieldList=self._values['nat_end_in_storage_format_fields'],
                userDefined=self._values['nat_end_in_storage_format_user_string']
            )),
            quotaExceeded=self._finalize_parameter(dict(
                fieldListDelimiter=self._values['nat_quota_exceeded_storage_format_delimiter'],
                type=self._values['nat_quota_exceeded_storage_format_type'],
                fieldList=self._values['nat_quota_exceeded_storage_format_fields'],
                userDefined=self._values['nat_quota_exceeded_storage_format_user_string']
            )),
            errors=self._finalize_parameter(dict(
                fieldListDelimiter=self._values['nat_errors_storage_format_delimiter'],
                type=self._values['nat_errors_storage_format_type'],
                fieldList=self._values['nat_errors_storage_format_fields'],
                userDefined=self._values['nat_errors_storage_format_user_string']
            )),
        ))
        return self._finalize_parameter(dict(
            logPublisher=self._values['nat_publisher'],
            logSubscriberId=self._values['nat_log_sub_id'],
            lsnLegacyMode=self._values['nat_lsn_legacy_mode'],
            quotaExceeded=self._values['nat_quota_exceeded_action'],
            startInboundSession=self._values['nat_start_in_action'],
            endInboundSession=self._values['nat_end_in_action'],
            errors=self._values['nat_errors_action'],
            endOutboundSession=self._finalize_parameter(dict(
                action=self._values['nat_end_out_action'],
                elements=self._values['nat_end_out_incl_dst_addr_port']
            )),
            startOutboundSession=self._finalize_parameter(dict(
                action=self._values['nat_start_out_action'],
                elements=self._values['nat_start_out_incl_dst_addr_port']
            )),
            format=tmp_format,
            rateLimit=tmp_rate
        ))


class ReportableChanges(Changes):
    returnables = [
        'auto_discovery',
        'bot_defense',
        'classification',
        'description',
        'dos_protection',
        'packet_filter',
        'protocol_inspection',
        'dns_security',
        'sip_security',
        'network_security',
        'nat'
    ]

    @staticmethod
    def _handle_dest_addr_port(item):
        if item is None:
            return None
        if item == ['destination']:
            return 'yes'
        if not item:
            return 'no'

    @staticmethod
    def _handle_rate(item):
        if item is None:
            return None
        if item == 4294967295:
            return 'indefinite'
        return str(item)

    @property
    def auto_discovery(self):
        if self._values['auto_discovery'] is None:
            return None
        return self._values['auto_discovery'].get('logPublisher')

    @property
    def bot_defense(self):
        return self._finalize_parameter(
            dict(publisher=self._values['bot_publisher'],
                 send_remote_challenge_failure_messages=flatten_boolean(self._values['bot_remote_chall_fail_msg']),
                 log_alarm=flatten_boolean(self._values['bot_log_alarm']),
                 log_block=flatten_boolean(self._values['bot_log_block']),
                 log_browser=flatten_boolean(self._values['bot_log_browser']),
                 log_browser_verification_action=flatten_boolean(self._values['bot_log_browser_verify']),
                 log_captcha=flatten_boolean(self._values['bot_log_captcha']),
                 log_challenge_failure_request=flatten_boolean(self._values['bot_log_challenge_failure']),
                 log_device_id_collection_request=flatten_boolean(self._values['bot_log_deviceid_coll_req']),
                 log_honeypot_page=flatten_boolean(self._values['bot_log_honey_pot']),
                 log_mobile_application=flatten_boolean(self._values['bot_log_mobile_app']),
                 log_none=flatten_boolean(self._values['bot_log_none']),
                 log_rate_limit=flatten_boolean(self._values['bot_log_rate_limit']),
                 log_redirect_to_pool=flatten_boolean(self._values['bot_log_redirect_to_pool']),
                 log_suspicious_browser=flatten_boolean(self._values['bot_log_suspect_browser']),
                 log_tcp_reset=flatten_boolean(self._values['bot_log_tcp_reset']),
                 log_trusted_bot=flatten_boolean(self._values['bot_log_trusted_bot']),
                 log_unknown=flatten_boolean(self._values['bot_log_unknown']),
                 log_untrusted_bot=flatten_boolean(self._values['bot_log_untrusted_bot'])
                 )
        )

    @property
    def classification(self):
        return self._finalize_parameter(
            dict(log_matches=flatten_boolean(self._values['classification_log']),
                 publisher=self._values['classification_pub'])
        )

    @property
    def dos_protection(self):
        return self._finalize_parameter(dict(
            application=self._values['dos_app_publisher'], network=self._values['dos_net_pub'],
            dns=self._values['dos_dns_pub'], sip=self._values['dos_sip_pub'])
        )

    @property
    def packet_filter(self):
        return self._finalize_parameter(
            dict(rate=self._values['packet_filter_rate'], publisher=self._values['packet_filter_pub'])
        )

    @property
    def protocol_inspection(self):
        return self._finalize_parameter(
            dict(log_packet=flatten_boolean(self._values['proto_inspect_log']),
                 publisher=self._values['proto_inspect_pub'])
        )

    @property
    def dns_security(self):
        tmp_format = self._filter_params(dict(
            delimiter=self._values['dns_storage_format_delimiter'],
            type=self._values['dns_storage_format_type'],
            fields=self._values['dns_storage_format_fields'],
            user_string=self._values['dns_storage_format_user_string']
        ))
        result = self._filter_params(dict(
            dns_sec_publisher=self._values['dns_sec_publisher'],
            log_dns_drop=flatten_boolean(self._values['dns_sec_log_dns_drop']),
            log_dns_filtered_drop=flatten_boolean(self._values['dns_sec_log_filter_drop']),
            log_dns_malformed=flatten_boolean(self._values['dns_sec_log_malformed']),
            log_dns_malicious=flatten_boolean(self._values['dns_sec_log_malicious']),
            log_dns_reject=flatten_boolean(self._values['dns_sec_log_dns_reject'])
        ))
        if tmp_format:
            result['storage_format'] = tmp_format
        if result:
            return result

    @property
    def sip_security(self):
        tmp_format = self._filter_params(dict(
            delimiter=self._values['sip_storage_format_delimiter'],
            type=self._values['sip_storage_format_type'],
            fields=self._values['sip_storage_format_fields'],
            user_string=self._values['sip_storage_format_user_string']
        ))
        result = self._filter_params(dict(
            log_sip_drop=flatten_boolean(self._values['sip_sec_log_sip_drop']),
            log_sip_global_failures=flatten_boolean(self._values['sip_sec_log_global_fail']),
            log_sip_malformed=flatten_boolean(self._values['sip_sec_log_malformed']),
            log_sip_redirect_responses=flatten_boolean(self._values['sip_sec_log_redirect_response']),
            log_sip_request_failures=flatten_boolean(self._values['sip_sec_log_sip_failure']),
            log_sip_server_errors=flatten_boolean(self._values['sip_sec_log_sip_server_err'])
        ))
        if tmp_format:
            result['storage_format'] = tmp_format
        if result:
            return result

    @property
    def network_security(self):
        tmp_format = self._filter_params(dict(
            delimiter=self._values['net_storage_format_delimiter'],
            type=self._values['net_storage_format_type'],
            fields=self._values['net_storage_format_fields'],
            user_string=self._values['net_storage_format_user_string']
        ))
        result = self._filter_params(dict(
            log_acl_match_accept=flatten_boolean(self._values['net_sec_log_acl_match_accept']),
            log_acl_match_drop=flatten_boolean(self._values['net_sec_log_acl_match_drop']),
            log_acl_match_reject=flatten_boolean(self._values['net_sec_log_acl_match_reject']),
            log_geo_always=flatten_boolean(self._values['net_sec_log_geo_always']),
            log_acl_to_box_deny=flatten_boolean(self._values['net_sec_rate_limit_log_acl_to_box_deny']),
            log_ip_errors=flatten_boolean(self._values['net_sec_log_ip_errors']),
            log_tcp_errors=flatten_boolean(self._values['net_sec_log_tcp_errors']),
            log_tcp_events=flatten_boolean(self._values['net_sec_log_tcp_events']),
            log_translation_fields=flatten_boolean(self._values['net_sec_log_translation_fields']),
            log_user_always=flatten_boolean(self._values['net_sec_log_user_always']),
            log_uuid_field=flatten_boolean(self._values['net_sec_log_uuid_field']),
            rate_limit_acl_match_accept=self._handle_rate(self._values['net_sec_rate_limit_acl_match_accept']),
            rate_limit_acl_match_drop=self._handle_rate(self._values['net_sec_rate_limit_acl_match_drop']),
            rate_limit_match_reject=self._handle_rate(self._values['net_sec_rate_limit_match_reject']),
            rate_limit_aggregate_rate=self._handle_rate(self._values['net_sec_rate_limit_aggregate_rate']),
            rate_limit_ip_errors=self._handle_rate(self._values['net_sec_rate_limit_ip_errors']),
            rate_limit_tcp_errors=self._handle_rate(self._values['net_sec_rate_limit_tcp_errors']),
            rate_limit_tcp_events=self._handle_rate(self._values['net_sec_rate_limit_tcp_events'])
        ))
        if tmp_format:
            result['storage_format'] = tmp_format
        if result:
            return result

    @property
    def nat(self):
        result = self._finalize_parameter(dict(
            publisher=self._values['nat_publisher'],
            log_subscriber_id=flatten_boolean(self._values['nat_log_sub_id']),
            lsn_legacy_mode=flatten_boolean(self._values['nat_lsn_legacy_mode']),
            rate_limit_aggregate_rate=self._handle_rate(self._values['nat_rate_limit_aggregate_rate']),
            rate_limit_end_inbound_session=self._handle_rate(self._values['nat_rate_limit_end_in_sess']),
            rate_limit_end_outbound_session=self._handle_rate(self._values['nat_rate_limit_end_out_sess']),
            rate_limit_errors=self._handle_rate(self._values['nat_rate_limit_errors']),
            rate_limit_quota_exceeded=self._handle_rate(self._values['nat_rate_limit_quota_exceeded']),
            rate_limit_start_inbound_session=self._handle_rate(self._values['nat_rate_limit_start_in_sess']),
            rate_limit_start_outbound_session=self._handle_rate(self._values['nat_rate_limit_start_out_sess']),
            start_outbound_session=self._finalize_parameter(dict(
                action=self._values['nat_start_out_action'],
                include_dest_addr_port=self._handle_dest_addr_port(self._values['nat_start_out_incl_dst_addr_port']),
                storage_format=self._finalize_parameter(dict(
                    delimiter=self._values['nat_start_out_storage_format_delimiter'],
                    type=self._values['nat_start_out_storage_format_type'],
                    fields=self._values['nat_start_out_storage_format_fields'],
                    user_string=self._values['nat_start_out_storage_format_user_string']
                ))
            )),
            end_outbound_session=self._finalize_parameter(dict(
                action=self._values['nat_end_out_action'],
                include_dest_addr_port=self._handle_dest_addr_port(self._values['nat_end_out_incl_dst_addr_port']),
                storage_format=self._finalize_parameter(dict(
                    delimiter=self._values['nat_end_out_storage_format_delimiter'],
                    type=self._values['nat_end_out_storage_format_type'],
                    fields=self._values['nat_end_out_storage_format_fields'],
                    user_string=self._values['nat_end_out_storage_format_user_string']
                ))
            )),
            start_inbound_session=self._finalize_parameter(dict(
                action=self._values['nat_start_in_action'],
                storage_format=self._finalize_parameter(dict(
                    delimiter=self._values['nat_start_in_storage_format_delimiter'],
                    type=self._values['nat_start_in_storage_format_type'],
                    fields=self._values['nat_start_in_storage_format_fields'],
                    user_string=self._values['nat_start_in_storage_format_user_string']
                ))
            )),
            end_inbound_session=self._finalize_parameter(dict(
                action=self._values['nat_end_in_action'],
                storage_format=self._finalize_parameter(dict(
                    delimiter=self._values['nat_end_in_storage_format_delimiter'],
                    type=self._values['nat_end_in_storage_format_type'],
                    fields=self._values['nat_end_in_storage_format_fields'],
                    user_string=self._values['nat_end_in_storage_format_user_string']
                ))
            )),
            quota_exceeded=self._finalize_parameter(dict(
                action=self._values['nat_quota_exceeded_action'],
                storage_format=self._finalize_parameter(dict(
                    delimiter=self._values['nat_quota_exceeded_storage_format_delimiter'],
                    type=self._values['nat_quota_exceeded_storage_format_type'],
                    fields=self._values['nat_quota_exceeded_storage_format_fields'],
                    user_string=self._values['nat_quota_exceeded_storage_format_user_string']
                ))
            )),
            errors=self._finalize_parameter(dict(
                action=self._values['nat_errors_action'],
                storage_format=self._finalize_parameter(dict(
                    delimiter=self._values['nat_errors_storage_format_delimiter'],
                    type=self._values['nat_errors_storage_format_type'],
                    fields=self._values['nat_errors_storage_format_fields'],
                    user_string=self._values['nat_errors_storage_format_user_string']
                ))
            ))
        ))

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

    @property
    def dns_sec_publisher(self):
        return cmp_str_with_none(self.want.dns_sec_publisher, self.have.dns_sec_publisher)

    @property
    def dns_storage_format_fields(self):
        return cmp_simple_list(self.want.dns_storage_format_fields, self.have.dns_storage_format_fields, cmp_order=True)

    @property
    def sip_sec_publisher(self):
        return cmp_str_with_none(self.want.sip_sec_publisher, self.have.sip_sec_publisher)

    @property
    def sip_storage_format_fields(self):
        return cmp_simple_list(self.want.sip_storage_format_fields, self.have.sip_storage_format_fields, cmp_order=True)

    @property
    def net_sec_publisher(self):
        return cmp_str_with_none(self.want.net_sec_publisher, self.have.net_sec_publisher)

    @property
    def net_storage_format_fields(self):
        return cmp_simple_list(self.want.net_storage_format_fields, self.have.net_storage_format_fields, cmp_order=True)

    @property
    def nat_publisher(self):
        return cmp_str_with_none(self.want.nat_publisher, self.have.nat_publisher)

    @property
    def nat_start_out_incl_dst_addr_port(self):
        return cmp_simple_list(self.want.nat_start_out_incl_dst_addr_port, self.have.nat_start_out_incl_dst_addr_port)

    @property
    def nat_end_out_incl_dst_addr_port(self):
        return cmp_simple_list(self.want.nat_end_out_incl_dst_addr_port, self.have.nat_end_out_incl_dst_addr_port)

    @property
    def nat_start_out_storage_format_fields(self):
        return cmp_simple_list(
            self.want.nat_start_out_storage_format_fields,
            self.have.nat_start_out_storage_format_fields, cmp_order=True
        )

    @property
    def nat_end_out_storage_format_fields(self):
        return cmp_simple_list(
            self.want.nat_end_out_storage_format_fields,
            self.have.nat_end_out_storage_format_fields, cmp_order=True
        )

    @property
    def nat_start_in_storage_format_fields(self):
        return cmp_simple_list(
            self.want.nat_start_in_storage_format_fields,
            self.have.nat_start_in_storage_format_fields, cmp_order=True
        )

    @property
    def nat_end_in_storage_format_fields(self):
        return cmp_simple_list(
            self.want.nat_end_in_storage_format_fields,
            self.have.nat_end_in_storage_format_fields, cmp_order=True
        )

    @property
    def nat_quota_exceeded_storage_format_fields(self):
        return cmp_simple_list(
            self.want.nat_quota_exceeded_storage_format_fields,
            self.have.nat_quota_exceeded_storage_format_fields, cmp_order=True
        )

    @property
    def nat_errors_storage_format_fields(self):
        return cmp_simple_list(
            self.want.nat_errors_storage_format_fields,
            self.have.nat_errors_storage_format_fields, cmp_order=True
        )


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
        dns_sec = params.pop('dns_security', None)
        sip_sec = params.pop('sip_security', None)
        net_sec = params.pop('network_security', None)

        uri = "/mgmt/tm/security/log/profile/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if dns_sec:
            self._create_dns_security(dns_sec)

        if sip_sec:
            self._create_sip_security(sip_sec)

        if net_sec:
            self._create_net_security(net_sec)

        return True

    def _create_dns_security(self, params):
        params['name'] = self.want.name
        params['partition'] = self.want.partition

        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/protocol-dns/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def _create_sip_security(self, params):
        params['name'] = self.want.name
        params['partition'] = self.want.partition

        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/protocol-sip/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def _create_net_security(self, params):
        params['name'] = self.want.name
        params['partition'] = self.want.partition

        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/network/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        params = self._add_missing_options(self.changes.api_params())
        dns_sec = params.pop('dns_security', None)
        sip_sec = params.pop('sip_security', None)
        net_sec = params.pop('network_security', None)

        if params:
            uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}"
            response = self.client.patch(uri, data=params)

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

        if dns_sec and self.have.dns_sec_exists:
            self._update_dns_security(dns_sec)
        elif dns_sec and not self.have.dns_sec_exists:
            self._create_dns_security(dns_sec)

        if sip_sec and self.have.sip_sec_exists:
            self._update_sip_security(sip_sec)
        elif sip_sec and not self.have.sip_sec_exists:
            self._create_sip_security(sip_sec)

        if net_sec and self.have.net_sec_exists:
            self._update_net_security(net_sec)
        elif net_sec and not self.have.net_sec_exists:
            self._create_net_security(net_sec)

        return True

    def _update_dns_security(self, params):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/protocol-dns/" \
              f"{transform_name(self.want.partition, self.want.name)}"

        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def _update_sip_security(self, params):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/protocol-sip/" \
              f"{transform_name(self.want.partition, self.want.name)}"

        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def _update_net_security(self, params):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/network/" \
              f"{transform_name(self.want.partition, self.want.name)}"

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

        result = ApiParameters(params=response['contents'])

        dns_sec = self.read_dns_security_from_device()
        sip_sec = self.read_sip_security_from_device()
        net_sec = self.read_network_security_from_device()

        if dns_sec:
            result.update({'dns_security': dns_sec})

        if sip_sec:
            result.update({'sip_security': sip_sec})

        if net_sec:
            result.update({'network_security': net_sec})

        return result

    def read_dns_security_from_device(self):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/protocol-dns/" \
              f"{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']

    def read_sip_security_from_device(self):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/protocol-sip/" \
              f"{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']

    def read_network_security_from_device(self):
        uri = f"/mgmt/tm/security/log/profile/{transform_name(self.want.partition, self.want.name)}/network/" \
              f"{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']


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
                    log_untrusted_bot=dict(type='bool')
                )
            ),
            dns_security=dict(
                type='dict',
                options=dict(
                    publisher=dict(),
                    log_dns_drop=dict(type='bool'),
                    log_dns_filtered_drop=dict(type='bool'),
                    log_dns_malformed=dict(type='bool'),
                    log_dns_malicious=dict(type='bool'),
                    log_dns_reject=dict(type='bool'),
                    storage_format=dict(
                        type='dict',
                        options=dict(
                            type=dict(
                                choices=['field-list', 'user-defined', 'none']
                            ),
                            delimiter=dict(),
                            fields=dict(
                                type='list',
                                elements='str'
                            ),
                            user_string=dict()
                        ),
                        required_if=[
                            ['type', 'user-defined', ['user_string']],
                            ['type', 'field-list', ['fields']],
                        ],
                        mutually_exclusive=[
                            ['fields', 'user_string'],
                            ['user_string', 'delimiter']
                        ]
                    )
                )
            ),
            sip_security=dict(
                type='dict',
                options=dict(
                    publisher=dict(),
                    log_sip_drop=dict(type='bool'),
                    log_sip_global_failures=dict(type='bool'),
                    log_sip_malformed=dict(type='bool'),
                    log_sip_redirect_responses=dict(type='bool'),
                    log_sip_request_failures=dict(type='bool'),
                    log_sip_server_errors=dict(type='bool'),
                    storage_format=dict(
                        type='dict',
                        options=dict(
                            type=dict(
                                choices=['field-list', 'user-defined', 'none']
                            ),
                            delimiter=dict(),
                            fields=dict(
                                type='list',
                                elements='str'
                            ),
                            user_string=dict()
                        ),
                        required_if=[
                            ['type', 'user-defined', ['user_string']],
                            ['type', 'field-list', ['fields']],
                        ],
                        mutually_exclusive=[
                            ['fields', 'user_string'],
                            ['user_string', 'delimiter']
                        ]
                    )
                )
            ),
            network_security=dict(
                type='dict',
                options=dict(
                    publisher=dict(),
                    log_acl_match_accept=dict(type='bool'),
                    log_acl_match_drop=dict(type='bool'),
                    log_acl_match_reject=dict(type='bool'),
                    log_geo_always=dict(type='bool'),
                    log_ip_errors=dict(type='bool'),
                    log_tcp_errors=dict(type='bool'),
                    log_tcp_events=dict(type='bool'),
                    log_acl_to_box_deny=dict(type='bool'),
                    log_translation_fields=dict(type='bool'),
                    log_user_always=dict(type='bool'),
                    log_uuid_field=dict(type='bool'),
                    rate_limit_acl_match_accept=dict(),
                    rate_limit_acl_match_drop=dict(),
                    rate_limit_match_reject=dict(),
                    rate_limit_aggregate_rate=dict(),
                    rate_limit_ip_errors=dict(),
                    rate_limit_tcp_errors=dict(),
                    rate_limit_tcp_events=dict(),
                    storage_format=dict(
                        type='dict',
                        options=dict(
                            type=dict(
                                choices=['field-list', 'user-defined', 'none']
                            ),
                            delimiter=dict(),
                            fields=dict(
                                type='list',
                                elements='str'
                            ),
                            user_string=dict()
                        ),
                        required_if=[
                            ['type', 'user-defined', ['user_string']],
                            ['type', 'field-list', ['fields']],
                        ],
                        mutually_exclusive=[
                            ['fields', 'user_string'],
                            ['user_string', 'delimiter']
                        ]
                    )

                )
            ),
            nat=dict(
                type='dict',
                options=dict(
                    log_subscriber_id=dict(type='bool'),
                    lsn_legacy_mode=dict(type='bool'),
                    publisher=dict(),
                    rate_limit_aggregate_rate=dict(),
                    rate_limit_start_outbound_session=dict(),
                    rate_limit_start_inbound_session=dict(),
                    rate_limit_end_inbound_session=dict(),
                    rate_limit_end_outbound_session=dict(),
                    rate_limit_quota_exceeded=dict(),
                    rate_limit_errors=dict(),
                    start_outbound_session=dict(
                        type='dict',
                        options=dict(
                            action=dict(
                                choices=['enabled', 'disabled', 'backup-allocation-only']
                            ),
                            include_dest_addr_port=dict(type='bool'),
                            storage_format=dict(
                                type='dict',
                                options=dict(
                                    type=dict(
                                        choices=['field-list', 'user-defined', 'none']
                                    ),
                                    delimiter=dict(),
                                    fields=dict(
                                        type='list',
                                        elements='str'
                                    ),
                                    user_string=dict()
                                ),
                                required_if=[
                                    ['type', 'user-defined', ['user_string']],
                                    ['type', 'field-list', ['fields']],
                                ],
                                mutually_exclusive=[
                                    ['fields', 'user_string'],
                                    ['user_string', 'delimiter']
                                ]
                            ),
                        )
                    ),
                    start_inbound_session=dict(
                        type='dict',
                        options=dict(
                            action=dict(
                                choices=['enabled', 'disabled', 'backup-allocation-only']
                            ),
                            storage_format=dict(
                                type='dict',
                                options=dict(
                                    type=dict(
                                        choices=['field-list', 'user-defined', 'none']
                                    ),
                                    delimiter=dict(),
                                    fields=dict(
                                        type='list',
                                        elements='str'
                                    ),
                                    user_string=dict()
                                ),
                                required_if=[
                                    ['type', 'user-defined', ['user_string']],
                                    ['type', 'field-list', ['fields']],
                                ],
                                mutually_exclusive=[
                                    ['fields', 'user_string'],
                                    ['user_string', 'delimiter']
                                ]
                            ),
                        )
                    ),
                    end_inbound_session=dict(
                        type='dict',
                        options=dict(
                            action=dict(
                                choices=['enabled', 'disabled', 'backup-allocation-only']
                            ),
                            storage_format=dict(
                                type='dict',
                                options=dict(
                                    type=dict(
                                        choices=['field-list', 'user-defined', 'none']
                                    ),
                                    delimiter=dict(),
                                    fields=dict(
                                        type='list',
                                        elements='str'
                                    ),
                                    user_string=dict()
                                ),
                                required_if=[
                                    ['type', 'user-defined', ['user_string']],
                                    ['type', 'field-list', ['fields']],
                                ],
                                mutually_exclusive=[
                                    ['fields', 'user_string'],
                                    ['user_string', 'delimiter']
                                ]
                            ),
                        )
                    ),
                    end_outbound_session=dict(
                        type='dict',
                        options=dict(
                            action=dict(
                                choices=['enabled', 'disabled', 'backup-allocation-only']
                            ),
                            include_dest_addr_port=dict(type='bool'),
                            storage_format=dict(
                                type='dict',
                                options=dict(
                                    type=dict(
                                        choices=['field-list', 'user-defined', 'none']
                                    ),
                                    delimiter=dict(),
                                    fields=dict(
                                        type='list',
                                        elements='str'
                                    ),
                                    user_string=dict()
                                ),
                                required_if=[
                                    ['type', 'user-defined', ['user_string']],
                                    ['type', 'field-list', ['fields']],
                                ],
                                mutually_exclusive=[
                                    ['fields', 'user_string'],
                                    ['user_string', 'delimiter']
                                ]
                            ),
                        )
                    ),
                    quota_exceeded=dict(
                        type='dict',
                        options=dict(
                            action=dict(
                                choices=['enabled', 'disabled']
                            ),
                            storage_format=dict(
                                type='dict',
                                options=dict(
                                    type=dict(
                                        choices=['field-list', 'user-defined', 'none']
                                    ),
                                    delimiter=dict(),
                                    fields=dict(
                                        type='list',
                                        elements='str'
                                    ),
                                    user_string=dict()
                                ),
                                required_if=[
                                    ['type', 'user-defined', ['user_string']],
                                    ['type', 'field-list', ['fields']],
                                ],
                                mutually_exclusive=[
                                    ['fields', 'user_string'],
                                    ['user_string', 'delimiter']
                                ]
                            ),
                        )
                    ),
                    errors=dict(
                        type='dict',
                        options=dict(
                            action=dict(
                                choices=['enabled', 'disabled']
                            ),
                            storage_format=dict(
                                type='dict',
                                options=dict(
                                    type=dict(
                                        choices=['field-list', 'user-defined', 'none']
                                    ),
                                    delimiter=dict(),
                                    fields=dict(
                                        type='list',
                                        elements='str'
                                    ),
                                    user_string=dict()
                                ),
                                required_if=[
                                    ['type', 'user-defined', ['user_string']],
                                    ['type', 'field-list', ['fields']],
                                ],
                                mutually_exclusive=[
                                    ['fields', 'user_string'],
                                    ['user_string', 'delimiter']
                                ]
                            ),
                        )
                    )
                )
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
            )
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
