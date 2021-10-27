# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.constants import (
    VELOS_BASE_HEADERS, VELOS_ROOT
)


def header(method):
    def wrap(self, *args, **kwargs):
        args = list(args)
        if 'scope' in kwargs:
            args[0] = kwargs['scope'] + args[0]
            kwargs.pop('scope')
        else:
            args[0] = VELOS_ROOT + args[0]
        if 'headers' not in kwargs:
            kwargs['headers'] = VELOS_BASE_HEADERS
            return method(self, *args, **kwargs)
        else:
            kwargs['headers'].update(VELOS_BASE_HEADERS)
            return method(self, *args, **kwargs)
    return wrap


class F5Client:
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.plugin = kwargs.get('client', None)

    @header
    def delete(self, url, **kwargs):
        return self.plugin.send_request(url, method='DELETE', **kwargs)

    @header
    def get(self, url, **kwargs):
        return self.plugin.send_request(url, method='GET', **kwargs)

    @header
    def patch(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='PATCH', data=data, **kwargs)

    @header
    def post(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='POST', data=data, **kwargs)

    @header
    def put(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='PUT', data=data, **kwargs)
