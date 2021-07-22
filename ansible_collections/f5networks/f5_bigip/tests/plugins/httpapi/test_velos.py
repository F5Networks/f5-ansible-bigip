# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest.mock import MagicMock
from unittest import TestCase

from ansible.errors import AnsibleConnectionFailure
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.f5networks.f5_bigip.tests.utils.common import connection_response
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.constants import VELOS_BASE_HEADERS

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


class TestVelosHttpapi(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.velos"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = MagicMock()
        self.connection.send = self.mock_send

    def test_login_raises_exception_when_username_and_password_are_not_provided(self):
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login(None, None)
        assert 'Username and password are required for login.' in str(res.exception)

    def test_login_raises_exception_when_invalid_token_response(self):
        self.connection.send.return_value = connection_response(
            {'errorMessage': 'ERROR'}, 200, VELOS_BASE_HEADERS
        )
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        assert "Authentication process failed, server returned: {'errorMessage': 'ERROR'}" in str(res.exception)

    def test_login_success_properties_populated(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(VELOS_BASE_HEADERS)
        self.connection.send.return_value = connection_response(
            load_fixture('velos_auth.json'), 200, xheader
        )

        self.connection.httpapi.login('foo', 'bar')

        assert self.connection.httpapi.access_token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        assert self.connection._auth == {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
