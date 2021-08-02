# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
author: Wojciech Wypior <w.wypior@f5.com>
httpapi: velos
short_description: HttpApi Plugin for VELOS devices
description:
- This HttpApi plugin provides methods to connect to VELOS devices over a HTTP(S)-based api.
options:
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
version_added: 1.1.0
"""

import json

from ansible.module_utils.basic import to_text
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.errors import AnsibleConnectionFailure

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.constants import (
    VELOS_LOGIN, VELOS_BASE_HEADERS
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        self.access_token = None

    def login(self, username, password):
        if username and password:
            response = self.send_request(VELOS_LOGIN, method='GET', headers=VELOS_BASE_HEADERS)
        else:
            raise AnsibleConnectionFailure('Username and password are required for login.')

        if response['code'] == 200 and 'X-Auth-Token' in response['headers'].keys():
            self.access_token = response['headers'].get('X-Auth-Token', None)
            if self.access_token:
                self.connection._auth = {'X-Auth-Token': self.access_token}
            else:
                raise AnsibleConnectionFailure('Server returned invalid response during connection authentication.')
        else:
            raise AnsibleConnectionFailure('Authentication process failed, server returned: {0}'.format(
                response['contents'])
            )

    def logout(self):
        # token removal to be added to VELOS, for now this is a placeholder
        pass

    def handle_httperror(self, exc):
        if exc.code == 401:
            if self.connection._auth is not None:
                # only attempt to refresh token if we were connected before not when we get 401 on first attempt
                self.connection._auth = None
                return True
        return False

    def send_request(self, url, method=None, **kwargs):
        body = kwargs.pop('data', None)
        # allow for empty json to be passed as payload, useful for some endpoints
        data = json.dumps(body) if body or body == {} else None
        try:
            self._display_request(method, url, body)
            response, response_data = self.connection.send(url, data, method=method, **kwargs)
            response_value = self._get_response_value(response_data)
            return dict(
                code=response.getcode(),
                contents=self._response_to_json(response_value),
                headers=dict(response.getheaders())
            )
        except HTTPError as e:
            return dict(code=e.code, contents=handle_errors(e))

    def _display_request(self, method, url, data=None):
        if data:
            self._display_message(
                'VELOS API Call: {0} to {1} with data {2}'.format(method, url, data)
            )
        else:
            self._display_message(
                'VELOS API Call: {0} to {1}'.format(method, url)
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
            raise F5ModuleError('Invalid JSON response: %s' % response_text)


def handle_errors(error):
    try:
        error_data = json.loads(error.read())
    except ValueError:
        error_data = error.read()

    if error_data:
        if "errors" in error_data:
            errors = error_data["errors"]["error"]
            error_text = "\n".join(
                (error["error-message"] for error in errors)
            )
        else:
            error_text = error_data
        return error_text
    return to_text(error)
