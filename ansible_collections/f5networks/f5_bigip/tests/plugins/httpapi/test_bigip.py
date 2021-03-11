# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest.mock import (
    MagicMock, ANY
)
from unittest import TestCase

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six import StringIO
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.f5_bigip.tests.utils.common import (
    connection_response, download_response
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


class TestBigIPHttpapi(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5_bigip.bigip"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = MagicMock()
        self.connection.send = self.mock_send

    def test_login_raises_exception_when_username_and_password_are_not_provided(self):
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login(None, None)
        assert 'Username and password are required for login.' in str(res.exception)

    def test_login_raises_exception_when_invalid_token_response(self):
        self.connection.send.return_value = connection_response(
            {'token': {'BAZ': 'BAR'}}
        )
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        assert 'Server returned invalid response during connection authentication.' in str(res.exception)

    def test_send_request_should_return_error_info_when_http_error_raises(self):
        self.connection.send.side_effect = HTTPError(
            'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )

        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        assert "Authentication process failed, server returned: {'errorMessage': 'ERROR'}" in str(res.exception)

    def test_login_success_properties_populated(self):
        self.connection.send.return_value = connection_response(
            load_fixture('tmos_auth_response.json')
        )

        self.connection.httpapi.login('foo', 'bar')

        assert self.connection.httpapi.access_token == 'P42ZHJN5HS5DH4KM4ENK3AFCLP'
        assert self.connection._auth == {'X-F5-Auth-Token': 'P42ZHJN5HS5DH4KM4ENK3AFCLP'}

    def test_get_telemetry_network_os(self):
        mock_response = MagicMock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.return_value = False

        assert self.connection.httpapi.telemetry() is False
        assert self.connection.httpapi.network_os() == self.pc.network_os

    def test_upload_file(self):
        self.connection.send.return_value = True
        binary_file = os.path.join(fixture_path, 'test_binary_file.mock')
        self.connection.httpapi.upload_file('/fake/path/to/upload', binary_file)

        self.connection.send.assert_called_once_with(
            '/fake/path/to/upload/test_binary_file.mock', ANY, method='POST',
            headers={'Content-Range': '0-307199/307200', 'Content-Type': 'application/octet-stream',
                     'Connection': 'keep-alive'
                     }
        )

    def test_upload_file_retry(self):
        self.connection.send.side_effect = [HTTPError(
            'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        ), True]
        binary_file = os.path.join(fixture_path, 'test_binary_file.mock')
        self.connection.httpapi.upload_file('/fake/path/to/upload', binary_file)

        self.connection.send.assert_called_with(
            '/fake/path/to/upload/test_binary_file.mock', ANY, method='POST',
            headers={'Content-Range': '0-307199/307200', 'Content-Type': 'application/octet-stream',
                     'Connection': 'keep-alive'
                     }
        )
        assert self.connection.send.call_count == 2

    def test_upload_file_total_failure(self):
        self.connection.send.side_effect = HTTPError(
            'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )
        binary_file = os.path.join(fixture_path, 'test_binary_file.mock')

        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.upload_file('/fake/path/to/upload', binary_file)

        assert 'Failed to upload file too many times.' in str(res.exception)
        assert self.connection.send.call_count == 3

    def test_download_file(self):
        self.connection.send.return_value = download_response('ab' * 50000)
        self.connection.download_file('/fake/path/to/download/fakefile', '/tmp/fakefile')
        self.connection.send.assert_called_with('/fake/path/to/download/fakefile', None,
                                                headers={'Content-Range': '0-99999/99999',
                                                         'Content-Type': 'application/octet-stream',
                                                         'Connection': 'keep-alive'}
                                                )
        assert os.stat('/tmp/fakefile').st_size == 100000
        # clean up
        os.remove('/tmp/fakefile')

    def test_download_file_http_error(self):
        self.connection.send.side_effect = [
            HTTPError('http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}'))
        ]

        with self.assertRaises(HTTPError) as res:
            self.connection.download_file('/fake/path/to/download/fakefile', '/tmp/fakefile')

        assert res.exception.code == 400
