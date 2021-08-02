# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

BASE_HEADERS = {'Content-Type': 'application/json'}
VELOS_BASE_HEADERS = {'Content-Type': 'application/yang-data+json'}

MANAGED_BY_ANNOTATION_VERSION = 'f5-ansible.version'
MANAGED_BY_ANNOTATION_MODIFIED = 'f5-ansible.last_modified'

LOGIN = '/mgmt/shared/authn/login'
LOGOUT = '/mgmt/shared/authz/tokens/'

VELOS_LOGIN = '/restconf/data/openconfig-system:system/aaa'
VELOS_ROOT = '/restconf/data'

PLATFORM = {
    'bigip': 'BIG-IP',
    'bigiq': 'BIG-IQ'
}

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

TEEM_ENDPOINT = 'product.apis.f5.com',
TEEM_KEY = 'mmhJU2sCd63BznXAXDh4kxLIyfIMm3Ar'
TEEM_TIMEOUT = 10
TEEM_VERIFY = False
