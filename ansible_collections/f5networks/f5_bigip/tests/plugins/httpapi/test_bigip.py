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

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError
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
        self.pc.network_os = 'f5networks.f5_bigip.bigip'
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
        assert self.connection.httpapi.network_os() == 'f5networks.f5_bigip.bigip'

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

    def test_upload_file_no_true_path_no_dest(self):
        self.connection.send.return_value = True
        string_to_upload = 'this is a string to be converted to file contents'
        self.connection.httpapi.upload_file('/fake/path/to/upload', string_to_upload, true_path=False)
        self.connection.send.assert_called_with(
            ANY, b'this is a string to be converted to file contents', method='POST',
            headers={'Content-Range': '0-48/49', 'Content-Type': 'application/octet-stream', 'Connection': 'keep-alive'}
        )

    def test_upload_file_no_true_path_dest_defined(self):
        self.connection.send.return_value = True
        string_to_upload = 'this is a string to be converted to file contents'
        self.connection.httpapi.upload_file(
            '/fake/path/to/upload', string_to_upload, dest='fake_file', true_path=False
        )
        self.connection.send.assert_called_with(
            '/fake/path/to/upload/fake_file', b'this is a string to be converted to file contents', method='POST',
            headers={'Content-Range': '0-48/49', 'Content-Type': 'application/octet-stream', 'Connection': 'keep-alive'}
        )

    def test_download_file(self):
        self.connection.send.return_value = download_response('ab' * 50000)
        self.connection.httpapi.download_file('/fake/path/to/download/fakefile', '/tmp/fakefile')
        self.connection.send.assert_called_with('/fake/path/to/download/fakefile', None,
                                                headers={'Content-Range': '0-99999/99999',
                                                         'Content-Type': 'application/octet-stream',
                                                         'Connection': 'keep-alive'}
                                                )
        assert os.stat('/tmp/fakefile').st_size == 100000
        # clean up
        os.remove('/tmp/fakefile')

    def test_download_large_file(self):
        h1 = {'Content-Range': '0-524288/1572864'}
        h2 = {'Content-Range': '524289-1048575/1572864'}
        h3 = {'Content-Range': '1048576-1572863/1572864'}
        self.connection.send.side_effect = [
            download_response('ab' * 50000, headers=h1),
            download_response('ab' * 50000, headers=h2),
            download_response('ab' * 50000, headers=h3),
            download_response('ab' * 50000, headers=h3)
        ]
        self.connection.httpapi.download_file('/fake/path/to/download/fakefile', '/tmp/fakefile')
        self.connection.send.called_with('/fake/path/to/download/fakefile', None,
                                         headers={'Content-Range': '0-524288/1572864',
                                                  'Content-Type': 'application/octet-stream',
                                                  'Connection': 'keep-alive'}
                                         )

        assert self.connection.send.call_count == 4
        assert os.stat('/tmp/fakefile').st_size == 300000
        # clean up
        os.remove('/tmp/fakefile')

    def test_download_file_http_error(self):
        self.connection.send.side_effect = [
            HTTPError('http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}'))
        ]

        with self.assertRaises(HTTPError) as res:
            self.connection.httpapi.download_file('/fake/path/to/download/fakefile', '/tmp/fakefile')

        assert res.exception.code == 400

    def test_download_asm_file(self):
        content = {'Content-Length': 524287}
        self.connection.send.return_value = download_response('ab' * 50000, headers=content)
        self.connection.httpapi.download_asm_file('/fake/path/to/download/fakefile', '/tmp/fakefile', 524287)
        self.connection.send.assert_called_with('/fake/path/to/download/fakefile', None,
                                                headers={'Content-Range': '0-524287/524287',
                                                         'Content-Type': 'application/octet-stream',
                                                         'Connection': 'keep-alive'}
                                                )
        assert os.stat('/tmp/fakefile').st_size == 100000
        # clean up
        os.remove('/tmp/fakefile')

    def test_download_asm_large_file(self):
        h1 = {'Content-Length': '524288'}
        h2 = {'Content-Length': '524286'}
        h3 = {'Content-Length': '524287'}
        self.connection.send.side_effect = [
            download_response('ab' * 50000, headers=h1),
            download_response('ab' * 50000, headers=h2),
            download_response('ab' * 50000, headers=h3),
            download_response('ab' * 50000, headers=h3)
        ]
        self.connection.httpapi.download_asm_file('/fake/path/to/download/fakefile', '/tmp/fakefile', 1572864)
        self.connection.send.called_with('/fake/path/to/download/fakefile', None,
                                         headers={'Content-Range': '0-524287/1572864',
                                                  'Content-Type': 'application/octet-stream',
                                                  'Connection': 'keep-alive'}
                                         )

        assert os.stat('/tmp/fakefile').st_size == 300000
        # clean up
        os.remove('/tmp/fakefile')

    def test_download_asm_file_no_content_length_raises(self):
        self.connection.send.return_value = download_response('ab' * 50000)
        with self.assertRaises(F5ModuleError) as res:
            self.connection.httpapi.download_asm_file('/fake/path/to/download/fakefile', '/tmp/fakefile', 524287)

        assert 'The Content-Length header is not present.' == str(res.exception)

    def test_download_asm_file_no_filesize_raises(self):
        with self.assertRaises(F5ModuleError) as res:
            self.connection.httpapi.download_asm_file('/fake/path/to/download/fakefile', '/tmp/fakefile', None)

        assert 'File size value cannot be None' == str(res.exception)

    def test_download_asm_file_invalid_content_length_raises(self):
        content = {'Content-Length': '-1'}
        self.connection.send.return_value = download_response('ab' * 50000, headers=content)
        with self.assertRaises(F5ModuleError) as res:
            self.connection.httpapi.download_asm_file('/fake/path/to/download/fakefile', '/tmp/fakefile', 524287)

        assert 'Invalid Content-Length value returned: -1 ,the value should be greater than 0' == str(res.exception)

    def test_logout_returns_none(self):
        self.connection._auth = None
        nothing = self.connection.httpapi.logout()
        assert nothing is None

    def test_logout_succeeds(self):
        self.connection.send.side_effect = [
            connection_response(load_fixture('tmos_auth_response.json')),
            connection_response({})
        ]
        self.connection.httpapi.login('foo', 'bar')
        assert self.connection._auth == {'X-F5-Auth-Token': 'P42ZHJN5HS5DH4KM4ENK3AFCLP'}

        self.connection.httpapi.logout()
        self.connection.send.assert_called_with(
            '/mgmt/shared/authz/tokens/P42ZHJN5HS5DH4KM4ENK3AFCLP', None, method='DELETE'
        )

    def test_handle_http_error(self):
        exc1 = HTTPError('http://bigip.local', 404, '', {}, StringIO('{"errorMessage": "not found"}'))
        res1 = self.connection.httpapi.handle_httperror(exc1)
        assert res1 == exc1

        exc2 = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"errorMessage": "not allowed"}'))
        res2 = self.connection.httpapi.handle_httperror(exc2)
        assert res2 is False

        self.connection._auth = {'X-F5-Auth-Token': 'P42ZHJN5HS5DH4KM4ENK3AFCLP'}
        exc3 = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"errorMessage": "not allowed"}'))
        res3 = self.connection.httpapi.handle_httperror(exc3)
        assert res3 is True
        assert self.connection._auth is None

    def test_resonse_to_json_raises(self):
        with self.assertRaises(F5ModuleError) as err:
            self.connection.httpapi._response_to_json('invalid json}')
        assert 'Invalid JSON response: invalid json}' in str(err.exception)

    def test_get_user(self):
        self.connection.send.return_value = connection_response(
            load_fixture('tmos_auth_response.json')
        )

        self.connection.httpapi.login('FakeUser1', 'fakepass')
        assert self.connection.httpapi.get_user() == 'FakeUser1'
