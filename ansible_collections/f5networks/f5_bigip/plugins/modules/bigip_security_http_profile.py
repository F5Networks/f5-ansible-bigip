#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_security_http_profile
short_description: Manage security HTTP profiles on a BIG-IP
description:
  - Manage security HTTP profiles on a BIG-IP.
version_added: 1.13.0
options:
  name:
    description:
      - Specifies the name of the security HTTP profile to manage.
    type: str
    required: True
  parent:
    description:
      - Specifies the profile from which this profile inherits settings.
      - When creating a new profile, if this parameter is not specified, the default
        is the system-supplied C(http_security) profile.
      - Once the parent profile is set it cannot be changed.
    type: str
  description:
    description:
      - Specifies descriptive text that identifies security HTTP profile.
    type: str
  evasion_techniques:
    description:
      - Specifies what action the system takes when it detects an evasion technique.
    type: dict
    suboptions:
      alarm:
        description:
          - When set to C(true), the system logs the request data whenever it detects an evasion technique.
        type: bool
      block:
        description:
          - When set to C(true), the system stops requests whenever it detects an evasion technique.
        type: bool
  file_type:
    description:
      - Specifies which file types the security profile considers legal,
        and specifies what action the system takes when it detects a request for an illegal file type.
    type: dict
    suboptions:
      alarm:
        description:
          - When set to C(true), the system logs the request data whenever it detects an illegal file type.
        type: bool
      block:
        description:
          - When set to C(true), the system stops requests whenever it detects an illegal file type.
        type: bool
      allowed:
        description:
          - Specifies a list of file types that are allowed by the system.
          - When defined, all but the file types in the C(allowed) list are considered illegal.
          - This parameter is mutually exclusive with C(disallowed).
        type: list
        elements: str
      disallowed:
        description:
          - Specifies a list of file types that are disallowed by the system.
          - When defined, only file types found in the disallowed list are considered illegal.
          - This parameter is mutually exclusive with C(allowed).
        type: list
        elements: str
  http_protocol_checks:
    description:
      - Specifies which validations the system should check and what action the system takes
        when it detects a request that is not formatted properly.
    type: dict
    suboptions:
      alarm:
        description:
          - When set to C(true), the system logs the request data whenever a request
            fails one of the enabled HTTP protocol checks.
        type: bool
      block:
        description:
          - When set to C(true), the system stops requests that fail one of the enabled HTTP protocol checks.
        type: bool
      bad_host_header:
        description:
          - When set to C(true), the system inspects requests to see whether they contain
            a non RFC compliant header value.
        type: bool
      bad_version:
        description:
          - When set to C(true), the system inspects requests to see whether they request information from a client using
            a legal HTTP protocol version number C(0.9 or higher).
        type: bool
      body_in_get_head:
        description:
          - When set to C(true), the system examines requests that use the HEAD or GET methods to see whether the requests
            contain data in their bodies, which is considered illegal.
        type: bool
      chunked_with_content_length:
        description:
          - When set to C(true), the system examines chunked requests for a content-length header,
            which is not permitted.
        type: bool
      content_length_is_positive:
        description:
          - When set to C(true), the system examines requests to see whether their content length value
            is greater than zero.
        type: bool
      header_name_without_value:
        description:
          - When set to C(true), the system checks requests for valueless header names, which are considered illegal.
        type: bool
      high_ascii_in_headers:
        description:
          - When set to C(true), the system inspects request headers for ASCII characters greater than 127,
            which are not permitted.
        type: bool
      host_header_is_ip:
        description:
          - When set to C(true), the system verifies the request's host header value is not an IP address.
        type: bool
      maximum_headers:
        description:
          - When set, the system compares the number of headers in the requests against the number specified here.
          - The valid value range is 1 -150.
        type: int
      null_in_body:
        description:
          - When set to C(true), the system inspects the request body to see whether it contains a Null character,
            which is not allowed.
        type: bool
      null_in_headers:
        description:
          - When set to C(true), the system inspects request headers to see whether they contain a Null character,
            which is not allowed.
        type: bool
      post_with_zero_length:
        description:
          - When set to C(true), the system examines POST method requests for no content-length header,
            and for a content length of 0.
        type: bool
      several_content_length:
        description:
          - When set to C(true), the system examines each request to see whether it has more than one content-length
            header, which is considered illegal.
        type: bool
      unparsable_content:
        description:
          - When set to C(true), the system examines requests for content the system cannot parse,
            which is not permitted.
        type: bool
  method:
    description:
      - Specifies which HTTP methods the security profile considers legal, and specifies what action the system takes
        when it detects a request using an illegal method.
    type: dict
    suboptions:
      alarm:
        description:
          - When set to C(true), the system logs the request data whenever a request uses an illegal method.
        type: bool
      block:
        description:
          - When set to C(true), the system stops requests that use an illegal method.
        type: bool
      allowed_methods:
        description:
          - Lists the HTTP methods considered legal by the security profile.
        type: list
        elements: str
  header:
    description:
      - Specifies which headers must appear in requests, and specifies what action the system takes when it
        detects a request without a mandatory header.
    type: dict
    suboptions:
      alarm:
        description:
          - When set to C(true), the system logs the request data whenever a request does not include a mandatory header.
        type: bool
      block:
        description:
          - When set to C(true), the system stops requests that do not include a mandatory header.
        type: bool
      mandatory_headers:
        description:
          - Lists the headers that must appear in requests to be considered legal by the security profile.
        type: list
        elements: str
  length:
    description:
      - Specifies the default maximum length settings the security profile considers legal, and specifies what
        action the system should take when it detects a request using an illegal length.
    type: dict
    suboptions:
      alarm:
        description:
          - When set to C(true), the system logs the request data whenever a request fails one of the length checks.
        type: bool
      block:
        description:
          - When set to C(true), the system stops requests that fail one of the length checks.
        type: bool
      post_data:
        description:
          - Indicates whether there is a maximum acceptable length, in bytes, for the POST data portion of a request.
          - To specify no length restriction, type C(0).
        type: int
      request:
        description:
          - Indicates whether there is a maximum acceptable length, in bytes, of a request, and if so, specifies it.
          - To specify no length restriction, type C(0).
        type: int
      uri:
        description:
          - Indicates whether there is a maximum acceptable length, in bytes, for a URL, and if so, specifies it.
          - To specify no length restriction, type C(0).
        type: int
      query_string:
        description:
          - Indicates whether there is a maximum acceptable length, in bytes, for the query string portion of a
            request, and if so, specifies it.
          - To specify no length restriction, type C(0).
        type: int
  response:
    description:
      - Configures the information to display when the security profile blocks a client request.
    type: dict
    suboptions:
      type:
        description:
          - Specifies which content, or URL, the system sends to the client in response to an illegal blocked request.
          - When set to C(default), specifies the system-supplied response text written in HTML.
          - When set to C(custom), specifies a modified response text set by the C(body) and C(header) parameters.
          - When set to C(redirect), specifies the system redirects the user to a specific web page
            instead of viewing a blocking page. The link to the page can be specified by the C(url) parameter.
          - When set to C(soap-fault), specifies the system-supplied response written in SOAP fault message structure.
            Use this type when a SOAP request is blocked due to an XML related violation.
          - When set to C(soap-fault) or C(default), the C(body) and C(header) parameters are ignored.
        type: str
        choices:
          - soap-fault
          - redirect
          - custom
          - default
      body:
        description:
          - Specifies the HTML code the system sends to the client in response to an illegal blocked request.
          - This parameter is required when C(type) is C(custom).
        type: str
      header:
        description:
          - Specifies the response headers the system sends to the client in response to
            an illegal blocked request.
          - This parameter is required when C(type) is C(custom).
        type: str
      url:
        description:
          - Specifies the particular URL to which the system redirects the user.
        type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the security HTTP profile is created.
      - When C(absent), ensures the security HTTP profile is removed.
    type: str
    choices:
      - absent
      - present
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create an HTTP security profile
  bigip_security_http_profile:
    name: test_http_profile
    description: 'this is a test profile'
    evasion_techniques:
      alarm: 'no'
      block: 'yes'
    file_type:
      block: 'yes'
      allowed:
        - 'zip'
        - 'js'
        - 'json'
    http_protocol_checks:
      bad_host_header: 'yes'
      bad_version: 'yes'
      body_in_get_head: 'no'
      high_ascii_in_headers: 'no'
    method:
      allowed_methods:
        - 'GET'
        - 'POST'
        - 'PATCH'
    header:
      mandatory_headers:
        - 'authorization'
    length:
      post_data: 0
      request: 2048
      uri: 512
    response:
      type: 'redirect'
      url: 'https://you-are-banned.net'

- name: Modify an HTTP security profile
  bigip_security_http_profile:
    name: test_http_profile
    file_type:
      disallowed:
        - 'zip'
        - 'js'
        - 'json'
    method:
      allowed_methods:
        - 'GET'
        - 'POST'
        - 'PATCH'
        - 'DELETE'

- name: Delete an HTTP security profile
  bigip_security_http_profile:
    name: test_http_profile
    state: absent
'''

RETURN = r'''
description:
  description:
    - Specifies descriptive text that identifies security HTTP profile.
  returned: changed
  type: str
  sample: 'this is a text'
parent:
  description:
    - Specifies the profile from which this profile inherits settings.
  returned: changed
  type: str
  sample: /Common/foo_profile
evasion_techniques:
  description:
    - The action the system takes when it detects an evasion technique.
  returned: changed
  type: complex
  contains:
    alarm:
      description:
        - The system logs the request data whenever it detects an evasion technique.
      returned: changed
      type: bool
      sample: true
    block:
      description:
        - The system stops requests whenever it detects an evasion technique.
      returned: changed
      type: bool
      sample: false
file_type:
  description:
    - The file types the security profile considers legal and action to take if an illegal file type has been detected.
  returned: changed
  type: complex
  contains:
    alarm:
      description:
        - The system logs the request data whenever it detects an illegal file type.
      returned: changed
      type: bool
      sample: true
    block:
      description:
        - The system stops requests whenever it detects an illegal file type.
      returned: changed
      type: bool
      sample: false
    allowed:
      description:
        - The list of file types that are disallowed by the system.
      returned: changed
      type: list
      sample: ['js', 'asp']
    disallowed:
      description:
        - The list of file types that are allowed by the system.
      returned: changed
      type: list
      sample: ['js', 'asp']
http_protocol_checks:
  description:
    - The validations the system should check and action to be taken if a violation is detected.
  returned: changed
  type: complex
  contains:
    alarm:
      description:
        - The system logs the request data whenever it detects an HTTP protocol violation.
      returned: changed
      type: bool
      sample: true
    block:
      description:
        - The system stops requests whenever it detects an HTTP protocol violation.
      returned: changed
      type: bool
      sample: false
    bad_host_header:
      description:
        - The system inspects requests to see whether they contain a non RFC compliant header value.
      returned: changed
      type: bool
      sample: true
    bad_version:
      description:
        - The system inspects requests to see whether they request information from a client using
          a legal HTTP protocol version number.
      returned: changed
      type: bool
      sample: true
    body_in_get_head:
      description:
        - The system examines requests that use the HEAD or GET methods to see whether the requests
          contain data in their bodies.
      returned: changed
      type: bool
      sample: true
    chunked_with_content_length:
      description:
        - The system examines chunked requests for a content-length header.
      returned: changed
      type: bool
      sample: true
    content_length_is_positive:
      description:
        - The system examines requests to see whether their content length value is greater than zero.
      returned: changed
      type: bool
      sample: true
    header_name_without_value:
      description:
        - The system checks requests for valueless header names.
      returned: changed
      type: bool
      sample: true
    high_ascii_in_headers:
      description:
        - The system inspects request headers for ASCII characters greater than 127.
      returned: changed
      type: bool
      sample: true
    host_header_is_ip:
      description:
        - The system verifies the request's host header value is not an IP address.
      returned: changed
      type: bool
      sample: true
    maximum_headers:
      description:
        - The system compares the number of headers in the requests against the number specified here.
      returned: changed
      type: int
      sample: 30
    null_in_body:
      description:
        - The system inspects the request body to see whether it contains a Null character.
      returned: changed
      type: bool
      sample: true
    null_in_headers:
      description:
        - The system inspects request headers to see whether they contain a Null character.
      returned: changed
      type: bool
      sample: true
    post_with_zero_length:
      description:
        - The system examines POST method requests for no content-length header.
      returned: changed
      type: bool
      sample: true
    several_content_length:
      description:
        - The system examines each request to see whether it has more than one content-length header.
      returned: changed
      type: bool
      sample: true
    unparsable_content:
      description:
        - The system examines requests for content the system cannot parse.
      returned: changed
      type: bool
      sample: true
method:
  description:
    - Specifies which HTTP methods the security profile considers legal.
  returned: changed
  type: complex
  contains:
    alarm:
      description:
        - The system logs the request data whenever a request uses an illegal method.
      returned: changed
      type: bool
      sample: true
    block:
      description:
        - The system stops requests that use an illegal method.
      returned: changed
      type: bool
      sample: false
    allowed_methods:
      description:
        - The HTTP methods considered legal by the security profile.
      returned: changed
      type: list
      sample: ['GET', 'PATCH']
header:
  description:
    - Specifies which headers must appear in requests.
  returned: changed
  type: complex
  contains:
    alarm:
      description:
        - The system logs the request data whenever a request does not include a mandatory header.
      returned: changed
      type: bool
      sample: true
    block:
      description:
        - The system stops requests that do not include a mandatory header.
      returned: changed
      type: bool
      sample: false
    mandatory_headers:
      description:
        - The headers that must appear in requests to be considered legal by the security profile.
      returned: changed
      type: list
      sample: ['cookie']
length:
  description:
    - The default maximum length settings the security profile considers legal.
  returned: changed
  type: complex
  contains:
    alarm:
      description:
        - The system logs the request data whenever a request fails one of the length checks.
      returned: changed
      type: bool
      sample: true
    block:
      description:
        - The system stops requests that fail one of the length checks.
      returned: changed
      type: bool
      sample: false
    post_data:
      description:
        - Maximum acceptable length, in bytes, for the POST data portion of a request.
      returned: changed
      type: int
      sample: 2048
    request:
      description:
        - Maximum acceptable length, in bytes, of a request.
      returned: changed
      type: int
      sample: 2048
    uri:
      description:
        - Maximum acceptable length, in bytes, for a URL.
      returned: changed
      type: int
      sample: 2048
    query_string:
      description:
        - Maximum acceptable length, in bytes, for the query string portion of a request.
      returned: changed
      type: int
      sample: 2048
response:
  description:
    - The information to display when the security profile blocks a client request.
  returned: changed
  type: complex
  contains:
    type:
      description:
        - The content, or URL, the system sends to the client in response to an illegal blocked request.
      returned: changed
      type: str
      sample: default
    body:
      description:
        - The HTML code the system sends to the client in response to an illegal blocked request.
      returned: changed
      type: str
      sample: "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected.</body></html>"
    header:
      description:
        - The response headers the system sends to the client in response to an illegal blocked request.
      returned: changed
      type: str
      sample: "HTTP/1.1 200 OK\nCache-Control: no-cache\nPragma: no-cache\nConnection: close"
    url:
      description:
        - The response headers that the system sends to the client in response to an illegal blocked request.
      returned: changed
      type: str
      sample: "https://you-are-banned.net"
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
    F5ModuleError, AnsibleF5Parameters, flatten_boolean, fq_name, transform_name
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'defaultsFrom': 'parent',
        'evasionTechniques': 'evasion_techniques',
        'fileTypes': 'file_type',
        'httpRfc': 'http_protocol_checks',
        'methods': 'method',
        'mandatoryHeaders': 'header',
        'maximumLength': 'length'
    }

    api_attributes = [
        'description',
        'defaultsFrom',
        'evasionTechniques',
        'fileTypes',
        'httpRfc',
        'methods',
        'mandatoryHeaders',
        'maximumLength',
        'response'
    ]

    returnables = [
        'description',
        'parent',
        'evasion_alarm',
        'evasion_block',
        'file_alarm',
        'file_block',
        'files_allowed',
        'files_disallowed',
        'http_check_alarm',
        'http_check_block',
        'http_check_bad_host_header',
        'http_check_bad_version',
        'http_check_body_in_get',
        'http_check_chunk_with_content_length',
        'http_check_content_length_positive',
        'http_check_header_no_value',
        'http_check_high_ascii',
        'http_check_header_is_ip',
        'http_check_max_headers',
        'http_check_null_in_body',
        'http_check_null_in_headers',
        'http_check_post_with_zero_length',
        'http_check_several_content_length',
        'http_check_unparsable_content',
        'method_alarm',
        'method_block',
        'allowed_methods',
        'header_alarm',
        'header_block',
        'mandatory_headers',
        'length_alarm',
        'length_block',
        'length_post_data',
        'length_query_string',
        'length_request',
        'length_uri',
        'response_type',
        'response_body',
        'response_headers',
        'response_url'
    ]

    updatables = [
        'description',
        'evasion_alarm',
        'evasion_block',
        'file_alarm',
        'file_block',
        'files_allowed',
        'files_disallowed',
        'http_check_alarm',
        'http_check_block',
        'http_check_bad_host_header',
        'http_check_bad_version',
        'http_check_body_in_get',
        'http_check_chunk_with_content_length',
        'http_check_content_length_positive',
        'http_check_header_no_value',
        'http_check_high_ascii',
        'http_check_header_is_ip',
        'http_check_max_headers',
        'http_check_null_in_body',
        'http_check_null_in_headers',
        'http_check_post_with_zero_length',
        'http_check_several_content_length',
        'http_check_unparsable_content',
        'method_alarm',
        'method_block',
        'allowed_methods',
        'header_alarm',
        'header_block',
        'mandatory_headers',
        'length_alarm',
        'length_block',
        'length_post_data',
        'length_query_string',
        'length_request',
        'length_uri',
        'response_type',
        'response_body',
        'response_headers',
        'response_url'
    ]


class ApiParameters(Parameters):
    @property
    def evasion_alarm(self):
        if self._values['evasion_techniques'] is None:
            return None
        return self._values['evasion_techniques'].get('alarm')

    @property
    def evasion_block(self):
        if self._values['evasion_techniques'] is None:
            return None
        return self._values['evasion_techniques'].get('block')

    @property
    def file_alarm(self):
        if self._values['file_type'] is None:
            return None
        return self._values['file_type'].get('alarm')

    @property
    def file_block(self):
        if self._values['file_type'] is None:
            return None
        return self._values['file_type'].get('block')

    @property
    def files_allowed(self):
        if self._values['file_type'] is None:
            return None
        if self._values['file_type'].get('allowed'):
            return self._values['file_type'].get('values')

    @property
    def files_disallowed(self):
        if self._values['file_type'] is None:
            return None
        if self._values['file_type'].get('disallowed'):
            return self._values['file_type'].get('values')

    @property
    def http_check_alarm(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('alarm')

    @property
    def http_check_block(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('block')

    @property
    def http_check_bad_host_header(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('badHostHeader')

    @property
    def http_check_bad_version(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('badVersion')

    @property
    def http_check_body_in_get(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('bodyInGetHead')

    @property
    def http_check_chunk_with_content_length(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('chunkedWithContentLength')

    @property
    def http_check_content_length_positive(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('contentLengthIsPositive')

    @property
    def http_check_header_no_value(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('headerNameWithoutValue')

    @property
    def http_check_high_ascii(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('highAsciiInHeaders')

    @property
    def http_check_header_is_ip(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('hostHeaderIsIp')

    @property
    def http_check_max_headers(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('maximumHeaders')

    @property
    def http_check_null_in_body(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('nullInBody')

    @property
    def http_check_null_in_headers(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('nullInHeaders')

    @property
    def http_check_post_with_zero_length(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('postWithZeroLength')

    @property
    def http_check_several_content_length(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('severalContentLength')

    @property
    def http_check_unparsable_content(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._values['http_protocol_checks'].get('unparsableContent')

    @property
    def method_alarm(self):
        if self._values['method'] is None:
            return None
        return self._values['method'].get('alarm')

    @property
    def method_block(self):
        if self._values['method'] is None:
            return None
        return self._values['method'].get('block')

    @property
    def allowed_methods(self):
        if self._values['method'] is None:
            return None
        return self._values['method'].get('values')

    @property
    def header_alarm(self):
        if self._values['header'] is None:
            return None
        return self._values['header'].get('alarm')

    @property
    def header_block(self):
        if self._values['header'] is None:
            return None
        return self._values['header'].get('block')

    @property
    def mandatory_headers(self):
        if self._values['header'] is None:
            return None
        return self._values['header'].get('values')

    @property
    def length_alarm(self):
        if self._values['length'] is None:
            return None
        return self._values['length'].get('alarm')

    @property
    def length_block(self):
        if self._values['length'] is None:
            return None
        return self._values['length'].get('block')

    @property
    def length_post_data(self):
        if self._values['length'] is None:
            return None
        return self._values['length'].get('postData')

    @property
    def length_query_string(self):
        if self._values['length'] is None:
            return None
        return self._values['length'].get('queryString')

    @property
    def length_request(self):
        if self._values['length'] is None:
            return None
        return self._values['length'].get('request')

    @property
    def length_uri(self):
        if self._values['length'] is None:
            return None
        return self._values['length'].get('uri')

    @property
    def response_type(self):
        if self._values['response'] is None:
            return None
        return self._values['response'].get('type')

    @property
    def response_body(self):
        if self._values['response'] is None:
            return None
        return self._values['response'].get('body')

    @property
    def response_headers(self):
        if self._values['response'] is None:
            return None
        return self._values['response'].get('headers')

    @property
    def response_url(self):
        if self._values['response'] is None:
            return None
        return self._values['response'].get('url')


class ModuleParameters(Parameters):
    @staticmethod
    def _handle_booleans(item):
        result = flatten_boolean(item)
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @staticmethod
    def _handle_length(item):
        if item is None:
            return None
        if item == 0:
            return 'any'
        return str(item)

    @property
    def parent(self):
        if self._values['parent'] is None:
            return None
        return fq_name(self.partition, self._values['parent'])

    @property
    def evasion_alarm(self):
        if self._values['evasion_techniques'] is None:
            return None
        return self._handle_booleans(self._values['evasion_techniques'].get('alarm'))

    @property
    def evasion_block(self):
        if self._values['evasion_techniques'] is None:
            return None
        return self._handle_booleans(self._values['evasion_techniques'].get('block'))

    @property
    def file_alarm(self):
        if self._values['file_type'] is None:
            return None
        return self._handle_booleans(self._values['file_type'].get('alarm'))

    @property
    def file_block(self):
        if self._values['file_type'] is None:
            return None
        return self._handle_booleans(self._values['file_type'].get('block'))

    @property
    def files_allowed(self):
        if self._values['file_type'] is None:
            return None
        return self._values['file_type'].get('allowed')

    @property
    def files_disallowed(self):
        if self._values['file_type'] is None:
            return None
        return self._values['file_type'].get('disallowed')

    @property
    def http_check_alarm(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('alarm'))

    @property
    def http_check_block(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('block'))

    @property
    def http_check_bad_host_header(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('bad_host_header'))

    @property
    def http_check_bad_version(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('bad_version'))

    @property
    def http_check_body_in_get(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('body_in_get_head'))

    @property
    def http_check_chunk_with_content_length(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('chunked_with_content_length'))

    @property
    def http_check_content_length_positive(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('content_length_is_positive'))

    @property
    def http_check_header_no_value(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('header_name_without_value'))

    @property
    def http_check_high_ascii(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('high_ascii_in_headers'))

    @property
    def http_check_header_is_ip(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('host_header_is_ip'))

    @property
    def http_check_max_headers(self):
        if self._values['http_protocol_checks'] is None:
            return None
        value = self._values['http_protocol_checks'].get('maximum_headers')
        if value:
            if value < 1 or value > 150:
                raise F5ModuleError(
                    "The maximum headers value value must be in range of 1 - 150."
                )
            return str(value)

    @property
    def http_check_null_in_body(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('null_in_body'))

    @property
    def http_check_null_in_headers(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('null_in_headers'))

    @property
    def http_check_post_with_zero_length(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('post_with_zero_length'))

    @property
    def http_check_several_content_length(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('several_content_length'))

    @property
    def http_check_unparsable_content(self):
        if self._values['http_protocol_checks'] is None:
            return None
        return self._handle_booleans(self._values['http_protocol_checks'].get('unparsable_content'))

    @property
    def method_alarm(self):
        if self._values['method'] is None:
            return None
        return self._handle_booleans(self._values['method'].get('alarm'))

    @property
    def method_block(self):
        if self._values['method'] is None:
            return None
        return self._handle_booleans(self._values['method'].get('block'))

    @property
    def allowed_methods(self):
        if self._values['method'] is None:
            return None
        return self._values['method'].get('allowed_methods')

    @property
    def header_alarm(self):
        if self._values['header'] is None:
            return None
        return self._handle_booleans(self._values['header'].get('alarm'))

    @property
    def header_block(self):
        if self._values['header'] is None:
            return None
        return self._handle_booleans(self._values['header'].get('block'))

    @property
    def mandatory_headers(self):
        if self._values['header'] is None:
            return None
        return self._values['header'].get('mandatory_headers')

    @property
    def length_alarm(self):
        if self._values['length'] is None:
            return None
        return self._handle_booleans(self._values['length'].get('alarm'))

    @property
    def length_block(self):
        if self._values['length'] is None:
            return None
        return self._handle_booleans(self._values['length'].get('block'))

    @property
    def length_post_data(self):
        if self._values['length'] is None:
            return None
        return self._handle_length(self._values['length'].get('post_data'))

    @property
    def length_query_string(self):
        if self._values['length'] is None:
            return None
        return self._handle_length(self._values['length'].get('query_string'))

    @property
    def length_request(self):
        if self._values['length'] is None:
            return None
        return self._handle_length(self._values['length'].get('request'))

    @property
    def length_uri(self):
        if self._values['length'] is None:
            return None
        return self._handle_length(self._values['length'].get('uri'))

    @property
    def response_type(self):
        if self._values['response'] is None:
            return None
        return self._values['response'].get('type')

    @property
    def response_body(self):
        if self._values['response'] is None:
            return None
        if self.response_type == 'default' or self.response_type == 'soap-fault':
            return None
        return self._values['response'].get('body')

    @property
    def response_headers(self):
        if self._values['response'] is None:
            return None
        if self.response_type == 'default' or self.response_type == 'soap-fault':
            return None
        return self._values['response'].get('header')

    @property
    def response_url(self):
        if self._values['response'] is None:
            return None
        return self._values['response'].get('url')


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
        result = self._filter_params(item)
        if result:
            return result


class UsableChanges(Changes):
    @property
    def evasion_techniques(self):
        return self._finalize_parameter(dict(alarm=self._values['evasion_alarm'], block=self._values['evasion_block']))

    @property
    def file_type(self):
        result = dict(alarm=self._values['file_alarm'], block=self._values['file_block'])
        if self._values['files_allowed']:
            result['allowed'] = True
            result['values'] = self._values['files_allowed']
        elif self._values['files_disallowed']:
            result['disallowed'] = True
            result['values'] = self._values['files_disallowed']
        return self._finalize_parameter(result)

    @property
    def http_protocol_checks(self):
        result = dict(
            alarm=self._values['http_check_alarm'],
            block=self._values['http_check_block'],
            badHostHeader=self._values['http_check_bad_host_header'],
            badVersion=self._values['http_check_bad_version'],
            bodyInGetHead=self._values['http_check_body_in_get'],
            chunkedWithContentLength=self._values['http_check_chunk_with_content_length'],
            contentLengthIsPositive=self._values['http_check_content_length_positive'],
            headerNameWithoutValue=self._values['http_check_header_no_value'],
            highAsciiInHeaders=self._values['http_check_high_ascii'],
            hostHeaderIsIp=self._values['http_check_header_is_ip'],
            maximumHeaders=self._values['http_check_max_headers'],
            nullInBody=self._values['http_check_null_in_body'],
            nullInHeaders=self._values['http_check_null_in_headers'],
            postWithZeroLength=self._values['http_check_post_with_zero_length'],
            severalContentLength=self._values['http_check_several_content_length'],
            unparsableContent=self._values['http_check_unparsable_content']
        )
        return self._finalize_parameter(result)

    @property
    def method(self):
        result = dict(
            alarm=self._values['method_alarm'],
            block=self._values['method_block'],
            values=self._values['allowed_methods']
        )
        return self._finalize_parameter(result)

    @property
    def header(self):
        result = dict(
            alarm=self._values['header_alarm'],
            block=self._values['header_block'],
            values=self._values['mandatory_headers']
        )
        return self._finalize_parameter(result)

    @property
    def length(self):
        result = dict(
            alarm=self._values['length_alarm'],
            block=self._values['length_block'],
            postData=self._values['length_post_data'],
            queryString=self._values['length_query_string'],
            request=self._values['length_request'],
            uri=self._values['length_uri']
        )
        return self._finalize_parameter(result)

    @property
    def response(self):
        result = dict(
            body=self._values['response_body'],
            headers=self._values['response_headers'],
            type=self._values['response_type'],
            url=self._values['response_url']
        )
        return self._finalize_parameter(result)


class ReportableChanges(Changes):
    returnables = [
        'description',
        'parent',
        'evasion_techniques',
        'file_type',
        'http_protocol_checks',
        'method',
        'header',
        'length',
        'response'
    ]

    @staticmethod
    def _handle_length(item):
        if item is None:
            return None
        if item == 'any':
            return 0
        return int(item)

    @property
    def evasion_techniques(self):
        result = dict(
            alarm=flatten_boolean(self._values['evasion_alarm']),
            block=flatten_boolean(self._values['evasion_block'])
        )
        return self._finalize_parameter(result)

    @property
    def file_type(self):
        result = dict(
            alarm=flatten_boolean(self._values['file_alarm']),
            block=flatten_boolean(self._values['file_block']),
            allowed=self._values['files_allowed'],
            disallowed=self._values['files_disallowed'],
        )
        return self._finalize_parameter(result)

    @property
    def http_protocol_checks(self):
        result = dict(
            alarm=flatten_boolean(self._values['http_check_alarm']),
            block=flatten_boolean(self._values['http_check_block']),
            bad_host_header=flatten_boolean(self._values['http_check_bad_host_header']),
            bad_version=flatten_boolean(self._values['http_check_bad_version']),
            body_in_get_head=flatten_boolean(self._values['http_check_body_in_get']),
            chunked_with_content_length=flatten_boolean(self._values['http_check_chunk_with_content_length']),
            content_length_is_positive=flatten_boolean(self._values['http_check_content_length_positive']),
            header_name_without_value=flatten_boolean(self._values['http_check_header_no_value']),
            high_ascii_in_headers=flatten_boolean(self._values['http_check_high_ascii']),
            host_header_is_ip=flatten_boolean(self._values['http_check_header_is_ip']),
            maximum_headers=self._values['http_check_max_headers'],
            null_in_body=flatten_boolean(self._values['http_check_null_in_body']),
            null_in_headers=flatten_boolean(self._values['http_check_null_in_headers']),
            post_with_zero_length=flatten_boolean(self._values['http_check_post_with_zero_length']),
            several_content_length=flatten_boolean(self._values['http_check_several_content_length']),
            unparsable_content=flatten_boolean(self._values['http_check_unparsable_content'])
        )
        return self._finalize_parameter(result)

    @property
    def method(self):
        result = dict(
            alarm=flatten_boolean(self._values['method_alarm']),
            block=flatten_boolean(self._values['method_block']),
            allowed_methods=self._values['allowed_methods']
        )
        return self._finalize_parameter(result)

    @property
    def header(self):
        result = dict(
            alarm=flatten_boolean(self._values['header_alarm']),
            block=flatten_boolean(self._values['header_block']),
            mandatory_headers=self._values['mandatory_headers']
        )
        return self._finalize_parameter(result)

    @property
    def length(self):
        result = dict(
            alarm=flatten_boolean(self._values['length_alarm']),
            block=flatten_boolean(self._values['length_block']),
            post_data=self._handle_length(self._values['length_post_data']),
            query_string=self._handle_length(self._values['length_query_string']),
            request=self._handle_length(self._values['length_request']),
            uri=self._handle_length(self._values['length_uri'])
        )
        return self._finalize_parameter(result)

    @property
    def response(self):
        result = dict(
            body=self._values['response_body'],
            headers=self._values['response_headers'],
            type=self._values['response_type'],
            url=self._values['response_url']
        )
        return self._finalize_parameter(result)


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:  # pragma: no cover
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
        uri = f"/mgmt/tm/security/http/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "/mgmt/tm/security/http/profile/"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = f"/mgmt/tm/security/http/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        uri = f"/mgmt/tm/security/http/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/mgmt/tm/security/http/profile/{transform_name(self.want.partition, self.want.name)}"
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
            evasion_techniques=dict(
                type='dict',
                options=dict(
                    alarm=dict(type='bool'),
                    block=dict(type='bool')
                ),
                required_one_of=[
                    ['alarm', 'block']
                ]
            ),
            file_type=dict(
                type='dict',
                options=dict(
                    alarm=dict(type='bool'),
                    block=dict(type='bool'),
                    allowed=dict(type='list', elements='str'),
                    disallowed=dict(type='list', elements='str')
                ),
                required_one_of=[
                    ['alarm', 'block', 'allowed', 'disallowed']
                ],
                mutually_exclusive=[
                    ['allowed', 'disallowed']
                ]
            ),
            http_protocol_checks=dict(
                type='dict',
                options=dict(
                    alarm=dict(type='bool'),
                    block=dict(type='bool'),
                    bad_host_header=dict(type='bool'),
                    bad_version=dict(type='bool'),
                    body_in_get_head=dict(type='bool'),
                    chunked_with_content_length=dict(type='bool'),
                    content_length_is_positive=dict(type='bool'),
                    header_name_without_value=dict(type='bool'),
                    high_ascii_in_headers=dict(type='bool'),
                    host_header_is_ip=dict(type='bool'),
                    maximum_headers=dict(type='int'),
                    null_in_body=dict(type='bool'),
                    null_in_headers=dict(type='bool'),
                    post_with_zero_length=dict(type='bool'),
                    several_content_length=dict(type='bool'),
                    unparsable_content=dict(type='bool')
                )
            ),
            method=dict(
                type='dict',
                options=dict(
                    alarm=dict(type='bool'),
                    block=dict(type='bool'),
                    allowed_methods=dict(type='list', elements='str'),
                ),
                required_one_of=[
                    ['alarm', 'block', 'allowed_methods']
                ],
            ),
            header=dict(
                type='dict',
                options=dict(
                    alarm=dict(type='bool'),
                    block=dict(type='bool'),
                    mandatory_headers=dict(type='list', elements='str'),
                ),
                required_one_of=[
                    ['alarm', 'block', 'mandatory_headers']
                ],
            ),
            length=dict(
                type='dict',
                options=dict(
                    alarm=dict(type='bool'),
                    block=dict(type='bool'),
                    post_data=dict(type='int'),
                    request=dict(type='int'),
                    uri=dict(type='int'),
                    query_string=dict(type='int')
                ),
                required_one_of=[
                    ['alarm', 'block', 'post_data', 'request', 'uri', 'query_string']
                ],
            ),
            response=dict(
                type='dict',
                options=dict(
                    type=dict(
                        choices=['soap-fault', 'redirect', 'custom', 'default']
                    ),
                    body=dict(),
                    header=dict(),
                    url=dict()
                ),
                required_if=[
                    ['type', 'redirect', ['url']],
                    ['type', 'custom', ['header', 'body']],
                ],
                required_one_of=[
                    ['type', 'body', 'url', 'header']
                ],
                mutually_exclusive=[
                    ['header', 'url'],
                    ['body', 'url']
                ]
            ),
            parent=dict(),
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
