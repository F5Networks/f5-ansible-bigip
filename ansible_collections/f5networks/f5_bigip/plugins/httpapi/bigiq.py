# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author: Wojciech Wypior <w.wypior@f5.com>
httpapi: bigip
short_description: HttpApi Plugin for BIG-IQ devices
description:
  - This HttpApi plugin provides methods to connect to BIG-IQ
    devices over a HTTP(S)-based api.
options:
  bigiq_provider:
    description:
    - The login provider used in communicating with BIG-IQ devices when the API connection
      is first established.
    - The provider can be either a name as configured on BIG-IQ or its corresponding UUID.
    - If the provider is not specified, the default C(local) value is assumed.
    default: local
    ini:
    - section: defaults
      key: f5_provider
    env:
    - name: F5_PROVIDER
    vars:
    - name: f5_provider
  send_telemetry:
    description:
      - If C(yes) anonymous telemetry data is sent to F5
    default: True
    ini:
    - section: defaults
      key: f5_telemetry
    env:
      - name: F5_TELEMETRY_OFF
    vars:
      - name: f5_telemetry
version_added: "1.0"
"""
import os
from ansible.module_utils.basic import to_text
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.errors import AnsibleConnectionFailure

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.constants import (
    LOGIN, LOGOUT, BASE_HEADERS
)

try:
    import json
except ImportError:
    import simplejson as json


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        self.access_token = None
        self.refresh_token = None

    def login(self, username, password):
        provider = self.get_option("bigiq_provider")

        if username and password:
            payload = {
                'username': username,
                'password': password,
            }
            if provider and provider != 'local':
                login_ref = self._get_login_ref(provider)
                payload.update(login_ref)
            response = self.send_request(LOGIN, method='POST', data=payload, headers=BASE_HEADERS)
        else:
            raise AnsibleConnectionFailure('Username and password are required for login.')

        if response['code'] == 200 and 'token' in response['contents']:
            self.access_token = response['contents']['token'].get('token', None)
            self.refresh_token = response['contents']['refreshToken'].get('token', None)
            if self.access_token:
                self.connection._auth = {'X-F5-Auth-Token': self.access_token}
            else:
                raise AnsibleConnectionFailure('Server returned invalid response during connection authentication.')
        else:
            raise AnsibleConnectionFailure('Authentication process failed, server returned: {0}'.format(
                response['contents'])
            )

    def logout(self):
        if not self.connection._auth:
            return
        token = self.connection._auth.get('X-F5-Auth-Token', None)
        logout_uri = '{0}{1}'.format(LOGOUT, token)
        self.send_request(logout_uri, method='DELETE')

    def handle_httperror(self, exc):
        if exc.code == 404:
            # 404 errors need to be handled upstream due to exists methods relying on it.
            # Other codes will be raised by underlying connection plugin.
            return exc
        if exc.code == 401:
            if self.connection._auth is not None:
                # only attempt to refresh token if we were connected before not when we get 401 on first attempt
                self.connection._auth = None
                self.token_refresh()
                return True
        return False

    def token_refresh(self):
        payload = {
            'refreshToken': {
                'token': self.refresh_token
            }
        }

        response = self.send_request("/mgmt/shared/authn/exchange", method='POST', data=payload, headers=BASE_HEADERS)

        if response['code'] == 200 and 'token' in response['contents']:
            self.access_token = response['contents']['token'].get('token', None)
            self.refresh_token = response['contents']['refreshToken'].get('token', None)
            if self.access_token:
                self.connection._auth = {'X-F5-Auth-Token': self.access_token}
            else:
                raise AnsibleConnectionFailure('Server returned invalid response during token refresh.')
        else:
            raise AnsibleConnectionFailure('Token refresh process failed, server returned: {0}'.format(
                response['contents'])
            )

    def send_request(self, url, method=None, **kwargs):
        body = kwargs.pop('data', None)
        data = json.dumps(body) if body else None

        try:
            self._display_request(method, url, body)
            response, response_data = self.connection.send(url, data, method=method, **kwargs)
            response_value = self._get_response_value(response_data)
            return dict(
                code=response.getcode(),
                contents=self._response_to_json(response_value),
                headers=response.getheaders()
            )

        except HTTPError as e:
            return dict(code=e.code, contents=json.loads(e.read()))

    def _display_request(self, method, url, data=None):
        if data:
            self._display_message(
                'BIG-IQ API Call: {0} to {1} with data {2}'.format(method, url, data)
            )
        else:
            self._display_message(
                'BIG-IQ API Call: {0} to {1}'.format(method, url)
            )

    def _display_message(self, msg):
        self.connection._log_messages(msg)

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ConnectionError('Invalid JSON response: %s' % response_text)

    def _get_login_ref(self, provider):
        info = self._read_providers_on_device()
        uuids = [os.path.basename(os.path.dirname(x['link'])) for x in info['providers'] if '-' in x['link']]
        if provider in uuids:
            link = self._get_login_ref_by_id(info, provider)
            if not link:
                raise F5ModuleError(
                    "Provider with the UUID {0} was not found.".format(provider)
                )
            return dict(
                loginReference=dict(
                    link=link
                )
            )
        names = [os.path.basename(os.path.dirname(x['link'])) for x in info['providers'] if '-' in x['link']]
        if names.count(provider) > 1:
            raise F5ModuleError(
                "Ambiguous bigiq_provider name provided. Please specify a specific provider name or UUID."
            )
        link = self._get_login_ref_by_name(info, provider)
        if not link:
            raise F5ModuleError(
                "Provider with the name '{0}' was not found.".format(provider)
            )
        return dict(
            loginReference=dict(
                link=link
            )
        )

    def _read_providers_on_device(self):
        result = self.send_request('/info/system', method='GET')
        return result['contents']

    def telemetry(self):
        return self.get_option('send_telemetry')

    def network_os(self):
        return self.connection._network_os

    @staticmethod
    def _get_login_ref_by_id(info, provider):
        provider = '/' + provider + '/'
        for x in info['providers']:
            if x['link'].find(provider) > -1:
                return x['link']

    @staticmethod
    def _get_login_ref_by_name(info, provider):
        for x in info['providers']:
            if x['name'] == provider:
                return x['link']
        return None
