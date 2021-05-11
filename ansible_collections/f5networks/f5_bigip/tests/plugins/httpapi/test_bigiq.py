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
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six import StringIO
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.f5_bigip.tests.utils.common import connection_response

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
        self.pc.network_os = "f5networks.f5_bigip.bigiq"
        self.connection = connection_loader.get("httpapi", self.pc, "/dev/null")
        self.mock_send = MagicMock()
        self.connection.send = self.mock_send

    def test_login_raises_exception_when_username_and_password_are_not_provided(self):
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login(None, None)
        assert 'Username and password are required for login.' in str(res.exception)

    def test_login_raises_exception_when_invalid_token_response(self):
        self.connection.send.return_value = connection_response(
            {'token': {'BAZ': 'BAR'},
             'refreshToken': {'BAZ': 'BAR'}}
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

    def test_get_login_ref_by_name(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_provider_list.json')
        )

        expected = {
            'loginReference':
                {'link':
                    'https://localhost/mgmt/cm/system/authn/providers/radius/'
                    '15633ac8-362c-4b05-b1f9-f77f3cd8921e/login'
                 }
        }

        result = self.connection.httpapi._get_login_ref('RadiusServer')
        assert result == expected

    def test_get_login_ref_by_id(self):
        self.connection.send.return_value = connection_response(
            load_fixture('load_provider_list.json')
        )

        expected = {
            'loginReference':
                {'link':
                    'https://localhost/mgmt/cm/system/authn/providers/radius/'
                    '15633ac8-362c-4b05-b1f9-f77f3cd8921e/login'
                 }
        }

        result = self.connection.httpapi._get_login_ref('15633ac8-362c-4b05-b1f9-f77f3cd8921e')
        assert result == expected

    def test_login_success_local_provider(self):
        self.connection.send.return_value = connection_response(load_fixture('local_auth_response.json'))

        token = "eyJraWQiOiJhZmExZDliOC1jN2NiLTQ2NWMtOTE0Yy00MWNkODgwZjM1YjEiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJCSU" \
                "ctSVEiLCJqdGkiOiJuaGpmanVqRU9FWnZqaWQtR2xUSW1RIiwic3ViIjoiYWRtaW4iLCJhdWQiOiIxNzIuMTguNy41NSIsI" \
                "mlhdCI6MTU5MzE4Nzg3MSwiZXhwIjoxNTkzMTg4MTcxLCJ1c2VyTmFtZSI6ImFkbWluIiwiYXV0aFByb3ZpZGVyTmFtZSI6" \
                "ImxvY2FsIiwidXNlciI6Imh0dHBzOi8vbG9jYWxob3N0L21nbXQvc2hhcmVkL2F1dGh6L3VzZXJzL2FkbWluIiwidHlwZSI" \
                "6IkFDQ0VTUyIsInRpbWVvdXQiOjMwMCwiZ3JvdXBSZWZlcmVuY2VzIjpbXX0.Ob1gwS93X0yE1Q5rKiHEpFl-5dcmFN8dR-" \
                "CLe_ghJaNT4zEWp4r6EdgQ57yrBCHqfoe2JMVJ9UYW7Dn8lJh1buDJLAOJ9l1ifUQo0rSKkSI1UwNyVI5KeHafclngz1MNH" \
                "G8HUB0vRySfDO5FhRjDrNyXL7CeOblog9qgVAsBOW60A9Tgx4vlFgDebzf46Pp_EO9Oes75oIQSkGdARuYbNtM72QwWNUO6" \
                "fiFo_L93-LOrQiWz87PECRkwq5C91sl4uiqdBGN2LRjwHcs3v2vNQbVTlABPnOsGLe14dZE4AZ_peNwIBIGL4JT_55rdohl" \
                "AKqQKCIgEDTB9xvQyOZgX9yO76FfTIpzg2tPLVomiaFHK1joFdzJ-jWWfBUdlKLgYbenwUD9VRyZncv6fTmJug_QSCc1FL8" \
                "4cw8Ab745kBiwOwpr5RwvRqMjDKJfQuyTX_CYQIt9j-RfrGAORqiSvlu7FUykIXdcnpO9WktEr6Y3MZl7Wj__kyngZ3nwM-NOM"
        refresh = "eyJraWQiOiJhZmExZDliOC1jN2NiLTQ2NWMtOTE0Yy00MWNkODgwZjM1YjEiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJC" \
                  "SUctSVEiLCJqdGkiOiI0MEFibElmZkNHWHJyT2xvSzJQYlpBIiwic3ViIjoiYWRtaW4iLCJhdWQiOiIxNzIuMTguNy41N" \
                  "SIsImlhdCI6MTU5MzE4Nzg3MSwiZXhwIjoxNTkzMjIzODcxLCJ1c2VyTmFtZSI6ImFkbWluIiwiYXV0aFByb3ZpZGVyTm" \
                  "FtZSI6ImxvY2FsIiwidXNlciI6Imh0dHBzOi8vbG9jYWxob3N0L21nbXQvc2hhcmVkL2F1dGh6L3VzZXJzL2FkbWluIiw" \
                  "idHlwZSI6IlJFRlJFU0giLCJ0aW1lb3V0IjozNjAwMCwiZ3JvdXBSZWZlcmVuY2VzIjpbXX0.VsMXT57oTIBSCHgfryjn" \
                  "wy8uckeYwqCjYumjvFEJkE4CEI2V_AwL-IYoLaogxrPSuV_CzkdrOvNZQlOrHoe2Mo_4xDPxPgu0sNrJqyc9hcfKwNOvi" \
                  "goGGKg1GsPicbuu9W7yf-FWE5KESsojOm_SSvNKMq3fwabqrTyy1JQ_fooKKJ25NPhQoxUmtoxy5V5CLU6glddi2qRTIl" \
                  "BcPY2UCEECMj1sVyvMRq28TPIo-C81FAy56lCZIx_UNl3Mp741j0C5SmNNexuze2E0BaioP7ICNvYlwTlykBIgLvcMYS3" \
                  "mbCANw9t-Ar55TQOZH3SInsnU5BmsGNqKVIlcEM4o3ENk3wOpxq8Qq5BGxQ1V5euzvq0Sc7JzZqa9JO7WpIStqfJoa76X" \
                  "fbEa2v1YJhro58FIROIuCxQGfVmnhzz6cQbFJHKMLyMzEXJOXEaMSmM9WkDDD8yzklJmHBW_mBnmbL9KlETGjCyZobe6z" \
                  "I7V8HYkgQ45XE4nqJSBe0GsjdkE"
        self.connection.httpapi.login('foo', 'bar')

        assert self.connection.httpapi.access_token == token
        assert self.connection.httpapi.refresh_token == refresh
        assert self.connection._auth == {'X-F5-Auth-Token': token}

    def test_login_success_radius_provider_by_name(self):
        self.connection.send.side_effect = [
            connection_response(load_fixture('load_provider_list.json')),
            connection_response(load_fixture('login_with_non_local_provider.json'))
        ]
        mock_response = MagicMock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.return_value = 'RadiusServer'

        self.connection.httpapi.login('baz', 'bar')

        token = "eyJraWQiOiJhZmExZDliOC1jN2NiLTQ2NWMtOTE0Yy00MWNkODgwZjM1YjEiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJCSU" \
                "ctSVEiLCJqdGkiOiJFNkhKdnZOUnpwSnNQenB4MVRYSjN3Iiwic3ViIjoicGF1bGEiLCJhdWQiOiIxNzIuMTguNy41NSIsIm" \
                "lhdCI6MTU5MzE4ODg1MywiZXhwIjoxNTkzMTg5MTUzLCJ1c2VyTmFtZSI6InBhdWxhIiwiYXV0aFByb3ZpZGVyTmFtZSI6Il" \
                "JhZGl1c1NlcnZlciIsInVzZXIiOiJodHRwczovL2xvY2FsaG9zdC9tZ210L2NtL3N5c3RlbS9hdXRobi9wcm92aWRlcnMvcm" \
                "FkaXVzLzE1NjMzYWM4LTM2MmMtNGIwNS1iMWY5LWY3N2YzY2Q4OTIxZS91c2Vycy8xYjIwNzQ2NS1lYWM4LTNiNWQtOGIxMi" \
                "1lMzM1ZmFhMGI1M2EiLCJ0eXBlIjoiQUNDRVNTIiwidGltZW91dCI6MzAwLCJncm91cFJlZmVyZW5jZXMiOltdfQ.IESe2Hp" \
                "LfZOMZJ5dS1U90jAPDB8gvmJXNNVkcYcL0WTFmJ9XdSTnuw7NbGddZPXBwH-VmA7v0lPLymb_RmQqDoSQ1nnD692oSlRVpC9Z" \
                "g3S1zA-6Ela3ChuIpnQU3ZY0XBDhCKGF_L-9ryC5QPrsCcwLYX-1u579yJlUzGPxxRU4CSp7Gz7-HpUqFVvCOzc5_mJbQD_td" \
                "0z2bbOUnl3m7IbTEBrB8q_svvCONleiGk15bTyLyP-KZKblSzF1Ypr73F5EHbJUS75zhLls6Zqm7XKPA_5ZXq9_YO-sXsKYOB" \
                "nGurYieXDF_o0EdmUFqNypUr0bJxlSv4IAbZRJFi-kNKcsRrUm-t5c2UBXITKyQsCx2dsAS6zSAxMGLEF87kahTlQuRZ9NCs3" \
                "bokAz1cmuntWhLq0GxOwcJf45_F70lmu5192DXUlbiz13CLMzWHHA4lpcgwrwrUl1zqnT5arb7vOeAXFUNK1Eiu2OFnbAgItx" \
                "634fj8EJCQWjIelvgm6y"
        refresh = "eyJraWQiOiJhZmExZDliOC1jN2NiLTQ2NWMtOTE0Yy00MWNkODgwZjM1YjEiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJCSU" \
                  "ctSVEiLCJqdGkiOiJsZ0wwU1FpSGVsZDBlTFVHQkREUENnIiwic3ViIjoicGF1bGEiLCJhdWQiOiIxNzIuMTguNy41NSIsI" \
                  "mlhdCI6MTU5MzE4ODg1MywiZXhwIjoxNTkzMjI0ODUzLCJ1c2VyTmFtZSI6InBhdWxhIiwiYXV0aFByb3ZpZGVyTmFtZSI6" \
                  "IlJhZGl1c1NlcnZlciIsInVzZXIiOiJodHRwczovL2xvY2FsaG9zdC9tZ210L2NtL3N5c3RlbS9hdXRobi9wcm92aWRlcnM" \
                  "vcmFkaXVzLzE1NjMzYWM4LTM2MmMtNGIwNS1iMWY5LWY3N2YzY2Q4OTIxZS91c2Vycy8xYjIwNzQ2NS1lYWM4LTNiNWQtOG" \
                  "IxMi1lMzM1ZmFhMGI1M2EiLCJ0eXBlIjoiUkVGUkVTSCIsInRpbWVvdXQiOjM2MDAwLCJncm91cFJlZmVyZW5jZXMiOltdf" \
                  "Q.OIGhcUBeaF5vD78y-tyNhxgfVUsto9UcuC6DhGmA5amNse9pQqXiTkmx3HiqPL8BcbzDaw3jbIAZb6_EXsEeQ8xlkp9Ld" \
                  "wnozRy_fanWrnfjuikR6v2fHotLA97sSDCp-JT876A-e1H-3_H7TvGPTeSzejnoq00xPrt49OkWbeFPnkisvmcDdqo1LEmI" \
                  "Bn0WR0ly2xuWBq-CWC-kiy5iBRhJyjxxTqRq7wiYgXS-YLw4noujcpHn5Em0v-JIVMu4vM4XipODMOUm-DAdxOoYngO8MAi" \
                  "j10U2fDHjv2iWNzVv_OQCA34y52y-wYftqQVqh0U4ddT_l89ib592JwAKOg13hsE4NKjtyJt0ZcGlWB2oJ-YLA2ZvuG2aoN" \
                  "bAit8dA31iaIDBPPMkE-SIUTIjvG--aibSFVeH-V4OgbNtX2hFKd58gF76khzBCboyG7xP-aV0qBZg2rQEzzgC4MjRL1-Ey" \
                  "z-ORDGts_LnnzAWoI1DBTKW22xwwpgFly3kmBBj"

        assert self.connection.httpapi.access_token == token
        assert self.connection.httpapi.refresh_token == refresh
        assert self.connection._auth == {'X-F5-Auth-Token': token}

    def test_login_success_radius_provider_by_id(self):
        self.connection.send.side_effect = [
            connection_response(load_fixture('load_provider_list.json')),
            connection_response(load_fixture('login_with_non_local_provider.json'))
        ]
        mock_response = MagicMock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.return_value = '15633ac8-362c-4b05-b1f9-f77f3cd8921e'

        self.connection.httpapi.login('baz', 'bar')

        token = "eyJraWQiOiJhZmExZDliOC1jN2NiLTQ2NWMtOTE0Yy00MWNkODgwZjM1YjEiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJCSU" \
                "ctSVEiLCJqdGkiOiJFNkhKdnZOUnpwSnNQenB4MVRYSjN3Iiwic3ViIjoicGF1bGEiLCJhdWQiOiIxNzIuMTguNy41NSIsIm" \
                "lhdCI6MTU5MzE4ODg1MywiZXhwIjoxNTkzMTg5MTUzLCJ1c2VyTmFtZSI6InBhdWxhIiwiYXV0aFByb3ZpZGVyTmFtZSI6Il" \
                "JhZGl1c1NlcnZlciIsInVzZXIiOiJodHRwczovL2xvY2FsaG9zdC9tZ210L2NtL3N5c3RlbS9hdXRobi9wcm92aWRlcnMvcm" \
                "FkaXVzLzE1NjMzYWM4LTM2MmMtNGIwNS1iMWY5LWY3N2YzY2Q4OTIxZS91c2Vycy8xYjIwNzQ2NS1lYWM4LTNiNWQtOGIxMi" \
                "1lMzM1ZmFhMGI1M2EiLCJ0eXBlIjoiQUNDRVNTIiwidGltZW91dCI6MzAwLCJncm91cFJlZmVyZW5jZXMiOltdfQ.IESe2Hp" \
                "LfZOMZJ5dS1U90jAPDB8gvmJXNNVkcYcL0WTFmJ9XdSTnuw7NbGddZPXBwH-VmA7v0lPLymb_RmQqDoSQ1nnD692oSlRVpC9Z" \
                "g3S1zA-6Ela3ChuIpnQU3ZY0XBDhCKGF_L-9ryC5QPrsCcwLYX-1u579yJlUzGPxxRU4CSp7Gz7-HpUqFVvCOzc5_mJbQD_td" \
                "0z2bbOUnl3m7IbTEBrB8q_svvCONleiGk15bTyLyP-KZKblSzF1Ypr73F5EHbJUS75zhLls6Zqm7XKPA_5ZXq9_YO-sXsKYOB" \
                "nGurYieXDF_o0EdmUFqNypUr0bJxlSv4IAbZRJFi-kNKcsRrUm-t5c2UBXITKyQsCx2dsAS6zSAxMGLEF87kahTlQuRZ9NCs3" \
                "bokAz1cmuntWhLq0GxOwcJf45_F70lmu5192DXUlbiz13CLMzWHHA4lpcgwrwrUl1zqnT5arb7vOeAXFUNK1Eiu2OFnbAgItx" \
                "634fj8EJCQWjIelvgm6y"
        refresh = "eyJraWQiOiJhZmExZDliOC1jN2NiLTQ2NWMtOTE0Yy00MWNkODgwZjM1YjEiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJCSU" \
                  "ctSVEiLCJqdGkiOiJsZ0wwU1FpSGVsZDBlTFVHQkREUENnIiwic3ViIjoicGF1bGEiLCJhdWQiOiIxNzIuMTguNy41NSIsI" \
                  "mlhdCI6MTU5MzE4ODg1MywiZXhwIjoxNTkzMjI0ODUzLCJ1c2VyTmFtZSI6InBhdWxhIiwiYXV0aFByb3ZpZGVyTmFtZSI6" \
                  "IlJhZGl1c1NlcnZlciIsInVzZXIiOiJodHRwczovL2xvY2FsaG9zdC9tZ210L2NtL3N5c3RlbS9hdXRobi9wcm92aWRlcnM" \
                  "vcmFkaXVzLzE1NjMzYWM4LTM2MmMtNGIwNS1iMWY5LWY3N2YzY2Q4OTIxZS91c2Vycy8xYjIwNzQ2NS1lYWM4LTNiNWQtOG" \
                  "IxMi1lMzM1ZmFhMGI1M2EiLCJ0eXBlIjoiUkVGUkVTSCIsInRpbWVvdXQiOjM2MDAwLCJncm91cFJlZmVyZW5jZXMiOltdf" \
                  "Q.OIGhcUBeaF5vD78y-tyNhxgfVUsto9UcuC6DhGmA5amNse9pQqXiTkmx3HiqPL8BcbzDaw3jbIAZb6_EXsEeQ8xlkp9Ld" \
                  "wnozRy_fanWrnfjuikR6v2fHotLA97sSDCp-JT876A-e1H-3_H7TvGPTeSzejnoq00xPrt49OkWbeFPnkisvmcDdqo1LEmI" \
                  "Bn0WR0ly2xuWBq-CWC-kiy5iBRhJyjxxTqRq7wiYgXS-YLw4noujcpHn5Em0v-JIVMu4vM4XipODMOUm-DAdxOoYngO8MAi" \
                  "j10U2fDHjv2iWNzVv_OQCA34y52y-wYftqQVqh0U4ddT_l89ib592JwAKOg13hsE4NKjtyJt0ZcGlWB2oJ-YLA2ZvuG2aoN" \
                  "bAit8dA31iaIDBPPMkE-SIUTIjvG--aibSFVeH-V4OgbNtX2hFKd58gF76khzBCboyG7xP-aV0qBZg2rQEzzgC4MjRL1-Ey" \
                  "z-ORDGts_LnnzAWoI1DBTKW22xwwpgFly3kmBBj"

        assert self.connection.httpapi.access_token == token
        assert self.connection.httpapi.refresh_token == refresh
        assert self.connection._auth == {'X-F5-Auth-Token': token}

    def test_token_refresh(self):
        token_1 = "eyJraWQiOiJkMzExNjIxNC1hOWRkLTQ4NTYtODI0MC05MDY1OTZjZWFkOTgiLCJhbGciOiJSUzM4NCJ9.eyJpc3Mi" \
                  "OiJCSUctSVEiLCJqdGkiOiJnTkNUd2VxLVFkS1ZMNzFraVN4OUZ3Iiwic3ViIjoiYWRtaW4iLCJhdWQiOiIxNzIuM" \
                  "TguMTYxLjQ3IiwiaWF0IjoxNjE0ODU5NjM4LCJleHAiOjE2MTQ4NTk5MzgsInVzZXJOYW1lIjoiYWRtaW4iLCJhdX" \
                  "RoUHJvdmlkZXJOYW1lIjoibG9jYWwiLCJ1c2VyIjoiaHR0cHM6Ly9sb2NhbGhvc3QvbWdtdC9zaGFyZWQvYXV0aHo" \
                  "vdXNlcnMvYWRtaW4iLCJ0eXBlIjoiQUNDRVNTIiwidGltZW91dCI6MzAwLCJncm91cFJlZmVyZW5jZXMiOltdfQ.F" \
                  "WZZ7w0vCH39mleCnMFvMuvCrX2l4eaH0sqINdeR7g1cv5_sFKvaJJcjA0UEYc0JjCbqC-k06mbu0dn3NxwDqpsimz" \
                  "_7MVwoKAYjuIz3KXIjokUPpCka_hrF5uZLpj53VHKp8vN2GQvSxVbftdqBw0jBrpLFJNWqitnEf8Ie_MDgMmX6SMu" \
                  "ZRwM0jU7Xlf3eTJq529gmeZoN6u2haAcA0jyuvK0lvWXspRqtmY1c-BHch4nix92L7jXWSe-s60jBuJn3A5dgRCUE" \
                  "YARMnjWXB5Xinj21cc8HQWv6i924NFuqMFZAkSMjJImFmroK5ng8uaTBC0dtV3szmozAS96LWGkSqPhevW9TuU0FS" \
                  "3EVbMftlneoSj_d0FUscrR_1QR5zACUKQ-CEEL_thWt4-BoQiksMsP-FoQU2eCkapYurKUp8Ya8YnTz-fAVDQXghl" \
                  "VBr2ideEm08i7mncGsyn-rMLu1uq4eBaAayDWq6gUOm45WdzTwAgdhoAyVKur2MtSs"
        token_2 = "eyJraWQiOiJkMzExNjIxNC1hOWRkLTQ4NTYtODI0MC05MDY1OTZjZWFkOTgiLCJhbGciOiJSUzM4NCJ9.eyJpc3Mi" \
                  "OiJCSUctSVEiLCJqdGkiOiJRMUdERkE4cHF4b3ZfamtlRk4yU2xnIiwic3ViIjoiYWRtaW4iLCJhdWQiOiIxNzIuM" \
                  "TguMTYxLjQ3IiwiaWF0IjoxNjE0ODU5NzcyLCJleHAiOjE2MTQ4NjAwNzIsInVzZXJOYW1lIjoiYWRtaW4iLCJhdX" \
                  "RoUHJvdmlkZXJOYW1lIjoibG9jYWwiLCJ1c2VyIjoiaHR0cHM6Ly9sb2NhbGhvc3QvbWdtdC9zaGFyZWQvYXV0aHo" \
                  "vdXNlcnMvYWRtaW4iLCJ0eXBlIjoiQUNDRVNTIiwidGltZW91dCI6MzAwLCJncm91cFJlZmVyZW5jZXMiOltdfQ.Q" \
                  "3A5MQfCnvVluFgvQbEUSzNsL-jtOwODopYcxA0HOOrCHYO2ec15t6fznVsiT71B-rAGEFdgi0ZMDB7SKWha6Wzv-1" \
                  "ELRX8PVi-SWTGylhQpXpu_ZWja0oqHHv7uxbAyiF0uZt62IW-taXqZ2Pw4vPShDX4APPefujVwULAovrjLet2dE0Y" \
                  "6rxTqoADtgnauZx5R-_cmHZH-hwdRunVh-TWRATVpbXUL5E8MjKwuCpguI3CHO_sKd3eaI7Tc60rCh-yO3YHJuvae" \
                  "FFw2ipcMpqR-eo62QmwrxA5ZAKgXxzYrdnkZ7x73hKvJh8aYZsa2YZSuzEz3QTkpO8mbGFcX1IWNdqt1ZMs-HiXr2" \
                  "SMHW7nOmWsBlB9ymStvvnqM_HO8BYg6CScj_XTv9cfZDiGWTtcZSSsEWb6l_If1yzTLEWUNpbYCwOG4OEcHKV8TXz" \
                  "1ie4m4TzxdeMUSROXPxkoUQKG0bVCY4vPThqpHUYIe-boxgAYqqNXjJr7pp65-XeAw"
        refresh = "eyJraWQiOiJkMzExNjIxNC1hOWRkLTQ4NTYtODI0MC05MDY1OTZjZWFkOTgiLCJhbGciOiJSUzM4NCJ9.eyJpc3Mi" \
                  "OiJCSUctSVEiLCJqdGkiOiJzSG45dVkzcnhKRGtVbTRVTmthRUxnIiwic3ViIjoiYWRtaW4iLCJhdWQiOiIxNzIuM" \
                  "TguMTYxLjQ3IiwiaWF0IjoxNjE0ODU5NjM4LCJleHAiOjE2MTQ4OTU2MzgsInVzZXJOYW1lIjoiYWRtaW4iLCJhdX" \
                  "RoUHJvdmlkZXJOYW1lIjoibG9jYWwiLCJ1c2VyIjoiaHR0cHM6Ly9sb2NhbGhvc3QvbWdtdC9zaGFyZWQvYXV0aHo" \
                  "vdXNlcnMvYWRtaW4iLCJ0eXBlIjoiUkVGUkVTSCIsInRpbWVvdXQiOjM2MDAwLCJncm91cFJlZmVyZW5jZXMiOltd" \
                  "fQ.MrRkh9U9ufsoHNYaArflbLjGhFt3hINeex_6vgvCUFJAeVEhEqnNVvQk9TGBZGw3hT6pNCPIeXJGaK9huFAn7Y" \
                  "q0wwuWaZykPmhBAhUASMJBijOBMkcLF3LmdNS7tl-xzM6pwlcmSf2aPy3qvcJM5BlwSuDFj6JoV64woEDE8pjIrBc" \
                  "U9onj-AMSNnvSpRzgVjE47aGs91Fx4cgWjd1LZti42TG3HBK9KNQ9WJbgWkN1ocNM2scFs_IiqrhmTjAjWv7ddVFY" \
                  "YVnVSLkz1z46FWSKeLWsXgMfJAbRLiDk8nmFq77QZGW-N9ct2ouz2xsLeS3_s0Ck4o432ZZUvWmlFxKyRNNJ8csj_" \
                  "RCYoIemP4iLfpMmSsODoMl2Tc32aFIILhbV7QgkqBIhWEgUDhPYRk8vsv18Hf81qMIrqsKNJaNoTYVtJMt6IR2slz" \
                  "Hd0IAmrQsum03JfcD-5CUWD0kQYeEDCjlPMnC_pnBgXnj21zWCdkCQ_UnFoKTirkthjOY0"

        self.connection.send.side_effect = [
            connection_response(load_fixture('local_auth_response_2.json')),
            connection_response(load_fixture('refresh_response.json'))
        ]
        mock_response = MagicMock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.return_value = 'local'

        self.connection.httpapi.login('baz', 'bar')
        assert self.connection.httpapi.access_token == token_1
        assert self.connection.httpapi.refresh_token == refresh
        assert self.connection._auth == {'X-F5-Auth-Token': token_1}

        self.connection.httpapi.token_refresh()
        assert self.connection.httpapi.access_token == token_2
        assert self.connection.httpapi.refresh_token == refresh
        assert self.connection._auth == {'X-F5-Auth-Token': token_2}

    def test_get_telemetry_network_os(self):
        mock_response = MagicMock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.return_value = False

        assert self.connection.httpapi.telemetry() is False
        assert self.connection.httpapi.network_os() == self.pc.network_os
