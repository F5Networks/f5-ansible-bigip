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
short_description: HttpApi Plugin for BIG-IP devices
description:
  - This HttpApi plugin provides methods to connect to BIG-IP
    devices over a HTTP(S)-based api.
options:
  bigip_provider:
    description:
    - The login provider used in communicating with BIG-IP devices when the API connection
      is first established.
    - If the provider is not specified, the default C(tmos) value is assumed.
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

from tempfile import NamedTemporaryFile

from ansible.module_utils.basic import to_text
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.errors import AnsibleConnectionFailure

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.constants import (
    LOGIN, LOGOUT, BASE_HEADERS
)
from ansible_collections.f5networks.f5_bigip.plugins.module_utils.common import F5ModuleError


try:
    import json
except ImportError:
    import simplejson as json


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        self.access_token = None
        self.user = None

    def login(self, username, password):
        provider = self.get_option("bigip_provider")

        if username and password:
            payload = {
                'username': username,
                'password': password,
                'loginProviderName': provider if provider else 'tmos'
            }
            self.user = username
            response = self.send_request(LOGIN, method='POST', data=payload, headers=BASE_HEADERS)
        else:
            raise AnsibleConnectionFailure('Username and password are required for login.')

        if response['code'] == 200 and 'token' in response['contents']:
            self.access_token = response['contents']['token'].get('token', None)
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
                headers=response.getheaders()
            )
        except HTTPError as e:
            return dict(code=e.code, contents=json.loads(e.read()))

    def upload_file(self, url, src, dest=None, true_path=True):
        """Upload a file to an arbitrary URL.

        This method is responsible for correctly chunking an upload request to an
        arbitrary file worker URL.

        Arguments:
            url (string): The URL to upload a file to.
            src (string): The file to be uploaded.
            dest (string): The file name to create on the remote device.
            true_path(bool) : Indicates if src is path or a string payload.

        Returns:
            bool: True on success. False otherwise.

        Raises:
            AnsibleConnectionFailure: Raised if ``retries`` limit is exceeded.
        """

        # This appears to be the largest chunk size that iControlREST can handle.
        #
        # The trade-off you are making by choosing a chunk size is speed, over size of
        # transmission. A lower chunk size will be slower because a smaller amount of
        # data is read from disk and sent via HTTP. Lots of disk reads are slower and
        # There is overhead in sending the request to the BIG-IP.
        #
        # Larger chunk sizes are faster because more data is read from disk in one
        # go, and therefore more data is transmitted to the BIG-IP in one HTTP request.
        #
        # If you are transmitting over a slow link though, it may be more reliable to
        # transmit many small chunks that fewer large chunks. It will clearly take
        # longer, but it may be more robust.
        basename = None
        chunk_size = 1024 * 7168
        start = 0
        retries = 0

        if true_path:
            size = os.stat(src).st_size
            if not dest:
                basename = os.path.basename(src)

        if not true_path:
            # This is a workaround to the ansible-connection limitation where only strings, numbers,
            # lists and dicts can go through JSON-RPC (the way ansible-connection and module talk to each other),
            # this means we need to cheat if we want to pass a string payload as a file to BIG-IP, this means
            # writing the data (strings) to a temporary file so it can be uploaded to via the connection plugin.
            tmp = NamedTemporaryFile()
            tmp.write(src.encode())
            tmp.seek(0)
            size = os.stat(tmp.name).st_size
            src = tmp.name
            if not dest:
                basename = os.path.basename(tmp.name)

        if not basename:
            basename = dest
        url = '{0}/{1}'.format(url.rstrip('/'), basename)

        with open(src, 'rb') as fileobj:
            while True:
                if retries == 3:
                    # Retries are used here to allow the REST API to recover if you kill
                    # an upload mid-transfer.
                    #
                    # There exists a case where retrying a new upload will result in the
                    # API returning the POSTed payload (in bytes) with a non-200 response
                    # code.
                    #
                    # Retrying (after seeking back to 0) seems to resolve this problem.
                    raise AnsibleConnectionFailure(
                        "Failed to upload file too many times."
                    )
                try:
                    file_slice = fileobj.read(chunk_size)
                    if not file_slice:
                        break
                    current_bytes = len(file_slice)
                    if current_bytes < chunk_size:
                        end = size
                    else:
                        end = start + current_bytes
                    headers = {
                        'Content-Range': '%s-%s/%s' % (start, end - 1, size),
                        'Content-Type': 'application/octet-stream',
                        'Connection': 'keep-alive'
                    }
                    self.connection.send(url, file_slice, method='POST', headers=headers)
                    start += current_bytes
                except HTTPError:
                    # You must seek back to the beginning of the file upon exception.
                    #
                    # If this is not done, then you risk uploading a partial file.
                    fileobj.seek(0)
                    retries += 1
        return True

    def download_asm_file(self, url, dest, file_size):
        """Download a large ASM file from the remote device

        This method handles issues with ASM file endpoints that allow
        downloads of ASM objects on the BIG-IP, as well as handles
        chunking of large files.

        Arguments:
            url (string): The URL to download.
            dest (string): The location on (Ansible controller) disk to store the file.
            file_size (integer): The size of the remote file.

        Returns:
            bool: No response on success. Fail otherwise.
        """
        if not file_size:
            raise F5ModuleError("File size value cannot be None")

        with open(dest, 'wb') as fileobj:
            chunk_size = 512 * 1024
            start = 0
            end = chunk_size - 1
            size = file_size

            while True:
                content_range = "%s-%s/%s" % (start, end, size)
                headers = {
                    'Content-Range': content_range,
                    'Content-Type': 'application/octet-stream',
                    'Connection': 'keep-alive'
                }
                response, response_buffer = self.connection.send(url, None, headers=headers)
                if response.status == 200:
                    if 'Content-Length' not in response.headers:
                        error_message = "The Content-Length header is not present."
                        raise F5ModuleError(error_message)
                    length = response.headers['Content-Length']
                    if int(length) > 0:
                        fileobj.write(response_buffer.getbuffer())
                    else:
                        error = "Invalid Content-Length value returned: %s ," \
                                "the value should be greater than 0" % length
                        raise F5ModuleError(error)
                if end == size:
                    break
                start += chunk_size
                if start >= size:
                    break
                if (end + chunk_size) > size:
                    end = size - 1
                else:
                    end = start + chunk_size - 1

    def download_file(self, url, dest):
        """Download a file from the remote device

        This method handles the chunking needed to download a file from
        a given URL on the BIG-IP.

        Arguments:
            url (string): The URL to download.
            dest (string): The location on (Ansible controller) disk to store the file.

        Returns:
            bool: True on success. False otherwise.
        """
        with open(dest, 'wb') as fileobj:
            chunk_size = 512 * 1024
            start = 0
            end = chunk_size - 1
            size = 0
            current_bytes = 0

            while True:
                try:
                    content_range = "%s-%s/%s" % (start, end, size)
                    headers = {
                        'Content-Range': content_range,
                        'Content-Type': 'application/octet-stream',
                        'Connection': 'keep-alive'
                    }
                    response, response_buffer = self.connection.send(url, None, headers=headers)
                    if response.status == 200:
                        # If the size is zero, then this is the first time through
                        # the loop and we don't want to write data because we
                        # haven't yet figured out the total size of the file.
                        if size > 0:
                            current_bytes += chunk_size
                            fileobj.write(response_buffer.getbuffer())
                    # Once we've downloaded the entire file, we can break out of
                    # the loop
                    if end == size:
                        break
                    crange = response.headers['Content-Range']
                    # Determine the total number of bytes to read.
                    if size == 0:
                        size = int(crange.split('/')[-1]) - 1
                        # If the file is smaller than the chunk_size, the BigIP
                        # will return an HTTP 400. Adjust the chunk_size down to
                        # the total file size...
                        if chunk_size > size:
                            end = size
                        # ...and pass on the rest of the code.
                        continue
                    start += chunk_size
                    if (current_bytes + chunk_size) > size:
                        end = size
                    else:
                        end = start + chunk_size - 1
                except HTTPError:
                    # Any HTTP error is fatal and will result in corrupted download.
                    raise
        return True

    def _display_request(self, method, url, data=None):
        if data:
            self._display_message(
                'BIG-IP API Call: {0} to {1} with data {2}'.format(method, url, data)
            )
        else:
            self._display_message(
                'BIG-IP API Call: {0} to {1}'.format(method, url)
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

    def telemetry(self):
        return self.get_option('send_telemetry')

    def network_os(self):
        return self.connection._network_os

    def get_user(self):
        return self.user
