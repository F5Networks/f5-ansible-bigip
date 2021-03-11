# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import json as _json

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.parsing.convert_bool import BOOLEANS_TRUE
from ansible.module_utils.six import iteritems
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import (
    generic_urlparse, Request, urlparse
)


from .common import F5ModuleError


def get_provider_argspec():
    return f5_provider_spec


def load_params(params):
    provider = params.get('provider') or dict()
    for key, value in iteritems(provider):
        if key in f5_argument_spec:
            if params.get(key) is None and value is not None:
                params[key] = value


f5_provider_spec = {
    'server': dict(
        required=True,
        fallback=(env_fallback, ['F5_SERVER'])
    ),
    'server_port': dict(
        type='int',
        default=443,
        fallback=(env_fallback, ['F5_SERVER_PORT', 'ANSIBLE_REMOTE_PORT'])
    ),
    'user': dict(
        required=True,
        fallback=(env_fallback, ['F5_USER', 'ANSIBLE_NET_USERNAME', 'ANSIBLE_REMOTE_USER'])
    ),
    'password': dict(
        required=True,
        no_log=True,
        aliases=['pass', 'pwd'],
        fallback=(env_fallback, ['F5_PASSWORD', 'ANSIBLE_NET_PASSWORD']),
    ),
    'validate_certs': dict(
        type='bool',
        default='yes',
        fallback=(env_fallback, ['F5_VALIDATE_CERTS'])
    ),
    'timeout': dict(type='int'),
    'auth_provider': dict(),
}

f5_argument_spec = {
    'provider': dict(type='dict', options=f5_provider_spec),
}


class F5BaseClient(object):
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        load_params(self.params)
        self._client = None

    @property
    def api(self):
        raise F5ModuleError("Management root must be used from the concrete product classes.")

    def reconnect(self):
        """Attempts to reconnect to a device

        The existing token from a ManagementRoot can become invalid if you,
        for example, upgrade the device (such as is done in the *_software
        module.

        This method can be used to reconnect to a remote device without
        having to re-instantiate the ArgumentSpec and AnsibleF5Client classes
        it will use the same values that were initially provided to those
        classes

        :return:
        :raises iControlUnexpectedHTTPError
        """
        self._client = None

    @staticmethod
    def validate_params(key, store):
        if key in store and store[key] is not None:
            return True
        else:
            return False

    def merge_provider_params(self):
        result = dict()
        provider = self.params.get('provider', None)
        if not provider:
            provider = {}

        self.merge_provider_server_param(result, provider)
        self.merge_provider_server_port_param(result, provider)
        self.merge_provider_validate_certs_param(result, provider)
        self.merge_provider_auth_provider_param(result, provider)
        self.merge_provider_user_param(result, provider)
        self.merge_provider_password_param(result, provider)

        return result

    def merge_provider_server_param(self, result, provider):
        if self.validate_params('server', provider):
            result['server'] = provider['server']
        elif self.validate_params('F5_SERVER', os.environ):
            result['server'] = os.environ['F5_SERVER']
        else:
            raise F5ModuleError('Server parameter cannot be None or missing, please provide a valid value')

    def merge_provider_server_port_param(self, result, provider):
        if self.validate_params('server_port', provider):
            result['server_port'] = provider['server_port']
        elif self.validate_params('F5_SERVER_PORT', os.environ):
            result['server_port'] = os.environ['F5_SERVER_PORT']
        else:
            result['server_port'] = 443

    def merge_provider_validate_certs_param(self, result, provider):
        if self.validate_params('validate_certs', provider):
            result['validate_certs'] = provider['validate_certs']
        elif self.validate_params('F5_VALIDATE_CERTS', os.environ):
            result['validate_certs'] = os.environ['F5_VALIDATE_CERTS']
        else:
            result['validate_certs'] = True
        if result['validate_certs'] in BOOLEANS_TRUE:
            result['validate_certs'] = True
        else:
            result['validate_certs'] = False

    def merge_provider_auth_provider_param(self, result, provider):
        if self.validate_params('auth_provider', provider):
            result['auth_provider'] = provider['auth_provider']
        elif self.validate_params('F5_AUTH_PROVIDER', os.environ):
            result['auth_provider'] = os.environ['F5_AUTH_PROVIDER']
        else:
            result['auth_provider'] = None

        # Handle a specific case of the user specifying ``|default(omit)``
        # as the value to the auth_provider.
        #
        # In this case, Ansible will inject the omit-placeholder value
        # and the module params incorrectly interpret this. This case
        # can occur when specifying ``|default(omit)`` for a variable
        # value defined in the ``environment`` section of a Play.
        #
        # An example of the omit placeholder is shown below.
        #
        #  __omit_place_holder__11bd71a2840bff144594b9cc2149db814256f253
        #
        if result['auth_provider'] is not None and '__omit_place_holder__' in result['auth_provider']:
            result['auth_provider'] = None

    def merge_provider_user_param(self, result, provider):
        if self.validate_params('user', provider):
            result['user'] = provider['user']
        elif self.validate_params('F5_USER', os.environ):
            result['user'] = os.environ.get('F5_USER')
        elif self.validate_params('ANSIBLE_NET_USERNAME', os.environ):
            result['user'] = os.environ.get('ANSIBLE_NET_USERNAME')
        else:
            result['user'] = None

    def merge_provider_password_param(self, result, provider):
        if self.validate_params('password', provider):
            result['password'] = provider['password']
        elif self.validate_params('F5_PASSWORD', os.environ):
            result['password'] = os.environ.get('F5_PASSWORD')
        elif self.validate_params('ANSIBLE_NET_PASSWORD', os.environ):
            result['password'] = os.environ.get('ANSIBLE_NET_PASSWORD')
        else:
            result['password'] = None


class Response(object):
    def __init__(self):
        self._content = None
        self.status = None
        self.headers = dict()
        self.url = None
        self.reason = None
        self.request = None
        self.msg = None

    @property
    def content(self):
        return self._content

    @property
    def raw_content(self):
        return self._content

    def json(self):
        return _json.loads(self._content or 'null')

    @property
    def ok(self):
        if self.status is not None and int(self.status) > 400:
            return False
        try:
            response = self.json()
            if 'code' in response and response['code'] > 400:
                return False
        except ValueError:
            pass
        return True


class iControlRestSession(object):
    """Represents a session that communicates with a BigIP.

    This acts as a loose wrapper around Ansible's ``Request`` class. We're doing
    this as interim work until we move to the httpapi connector.
    """
    def __init__(self, headers=None, use_proxy=True, force=False, timeout=120,
                 validate_certs=True, url_username=None, url_password=None,
                 http_agent=None, force_basic_auth=False, follow_redirects='urllib2',
                 client_cert=None, client_key=None, cookies=None):
        self.request = Request(
            headers=headers,
            use_proxy=use_proxy,
            force=force,
            timeout=timeout,
            validate_certs=validate_certs,
            url_username=url_username,
            url_password=url_password,
            http_agent=http_agent,
            force_basic_auth=force_basic_auth,
            follow_redirects=follow_redirects,
            client_cert=client_cert,
            client_key=client_key,
            cookies=cookies
        )
        self.last_url = None

    def get_headers(self, result):
        try:
            return dict(result.getheaders())
        except AttributeError:
            return result.headers

    def update_response(self, response, result):
        response.headers = self.get_headers(result)
        response._content = result.read()
        response.status = result.getcode()
        response.url = result.geturl()
        response.msg = "OK (%s bytes)" % response.headers.get('Content-Length', 'unknown')

    def send(self, method, url, **kwargs):
        response = Response()

        # Set the last_url called
        #
        # This is used by the object destructor to erase the token when the
        # ModuleManager exits and destroys the iControlRestSession object
        self.last_url = url

        body = None
        data = kwargs.pop('data', None)
        json = kwargs.pop('json', None)

        if not data and json is not None:
            self.request.headers['Content-Type'] = 'application/json'
            body = _json.dumps(json)
            if not isinstance(body, bytes):
                body = body.encode('utf-8')
        if data:
            body = data
        if body:
            kwargs['data'] = body

        try:
            result = self.request.open(method, url, **kwargs)
        except HTTPError as e:
            # Catch HTTPError delivered from Ansible
            #
            # The structure of this object, in Ansible 2.8 is
            #
            # HttpError {
            #   args
            #   characters_written
            #   close
            #   code
            #   delete
            #   errno
            #   file
            #   filename
            #   filename2
            #   fp
            #   getcode
            #   geturl
            #   hdrs
            #   headers
            #   info
            #   msg
            #   name
            #   reason
            #   strerror
            #   url
            #   with_traceback
            # }
            self.update_response(response, e)
            return response

        self.update_response(response, result)
        return response

    def delete(self, url, **kwargs):
        return self.send('DELETE', url, **kwargs)

    def get(self, url, **kwargs):
        return self.send('GET', url, **kwargs)

    def patch(self, url, data=None, **kwargs):
        return self.send('PATCH', url, data=data, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.send('POST', url, data=data, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.send('PUT', url, data=data, **kwargs)

    def __del__(self):
        if self.last_url is None:
            return
        token = self.request.headers.get('X-F5-Auth-Token', None)
        if not token:
            return
        try:
            p = generic_urlparse(urlparse(self.last_url))
            uri = "https://{0}:{1}/mgmt/shared/authz/tokens/{2}".format(
                p['hostname'], p['port'], token
            )
            self.delete(uri)
        except ValueError:
            pass


def download_asm_file(client, url, dest, file_size):
    """Download a large ASM file from the remote device

    This method handles issues with ASM file endpoints that allow
    downloads of ASM objects on the BIG-IP, as well as handles
    chunking of large files.

    Arguments:
        client (object): The F5RestClient connection object.
        url (string): The URL to download.
        dest (string): The location on (Ansible controller) disk to store the file.
        file_size (integer): The size of the remote file.

    Returns:
        bool: No response on success. Fail otherwise.
    """

    with open(dest, 'wb') as fileobj:
        chunk_size = 512 * 1024
        start = 0
        end = chunk_size - 1
        size = file_size
        # current_bytes = 0

        while True:
            content_range = "%s-%s/%s" % (start, end, size)
            headers = {
                'Content-Range': content_range,
                'Content-Type': 'application/json'
            }
            data = {
                'headers': headers,
                'verify': False,
                'stream': False
            }

            response = client.api.get(url, headers=headers, json=data)
            if response.status == 200:
                if 'Content-Length' not in response.headers:
                    error_message = "The Content-Length header is not present."
                    raise F5ModuleError(error_message)
                length = response.headers['Content-Length']
                if int(length) > 0:
                    fileobj.write(response.content)
                else:
                    error = "Invalid Content-Length value returned: %s ," \
                            "the value should be greater than 0" % length
                    raise F5ModuleError(error)
                # fileobj.write(response.raw_content)
            if end == size:
                break
            start += chunk_size
            if start >= size:
                break
            if (end + chunk_size) > size:
                end = size - 1
            else:
                end = start + chunk_size - 1


def download_file(client, url, dest):
    """Download a file from the remote device

    This method handles the chunking needed to download a file from
    a given URL on the BIG-IP.

    Arguments:
        client (object): The F5RestClient connection object.
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
            content_range = "%s-%s/%s" % (start, end, size)
            headers = {
                'Content-Range': content_range,
                'Content-Type': 'application/octet-stream'
            }
            data = {
                'headers': headers,
                'verify': False,
                'stream': False
            }
            response = client.api.get(url, headers=headers, json=data)
            if response.status == 200:
                # If the size is zero, then this is the first time through
                # the loop and we don't want to write data because we
                # haven't yet figured out the total size of the file.
                if size > 0:
                    current_bytes += chunk_size
                    fileobj.write(response.raw_content)
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
    return True


def tmos_version(client):
    uri = "https://{0}:{1}/mgmt/tm/sys/".format(
        client.provider['server'],
        client.provider['server_port'],
    )
    resp = client.api.get(uri)

    try:
        response = resp.json()
    except ValueError as ex:
        raise F5ModuleError(str(ex))

    if 'code' in response and response['code'] in [400, 403]:
        if 'message' in response:
            raise F5ModuleError(response['message'])
        else:
            raise F5ModuleError(resp.content)

    to_parse = urlparse(response['selfLink'])
    query = to_parse.query
    version = query.split('=')[1]
    return version


def module_provisioned(client, module_name):
    provisioned = modules_provisioned(client)
    if module_name in provisioned:
        return True
    return False


def modules_provisioned(client):
    """Returns a list of all provisioned modules

    Args:
        client: Client connection to the BIG-IP

    Returns:
        A list of provisioned modules in their short name for.
        For example, ['afm', 'asm', 'ltm']
    """
    uri = "https://{0}:{1}/mgmt/tm/sys/provision".format(
        client.provider['server'],
        client.provider['server_port']
    )
    resp = client.api.get(uri)

    try:
        response = resp.json()
    except ValueError as ex:
        raise F5ModuleError(str(ex))

    if 'code' in response and response['code'] in [400, 403]:
        if 'message' in response:
            raise F5ModuleError(response['message'])
        else:
            raise F5ModuleError(resp.content)
    if 'items' not in response:
        return []
    return [x['name'] for x in response['items'] if x['level'] != 'none']
