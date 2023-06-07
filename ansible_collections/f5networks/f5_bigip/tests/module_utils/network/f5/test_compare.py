# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from unittest import TestCase

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.compare import (
    cmp_simple_list, cmp_str_with_none, compare_dictionary, compare_complex_list,
    nested_diff
)


class TestCompareFunctions(TestCase):
    def test_cmp_simple_list(self):
        res1 = cmp_simple_list(None, ['something'])
        res2 = cmp_simple_list('none', None)
        res3 = cmp_simple_list('', ['something'])
        res4 = cmp_simple_list(['want'], None)
        res5 = cmp_simple_list(['want'], ['have'])
        res6 = cmp_simple_list(['want'], ['want'])

        assert res1 is None and res2 is None and res6 is None
        assert res3 == []
        assert res4 == res5 == ['want']

    def test_cmp_str_with_none(self):
        res1 = cmp_str_with_none(None, 'something')
        res2 = cmp_str_with_none('', None)
        res3 = cmp_str_with_none('want', 'have')

        assert res1 is None and res2 is None
        assert res3 == 'want'

    def test_compare_complex_list(self):
        res1 = compare_complex_list([], None)
        res2 = compare_complex_list(None, ['foo'])
        res3 = compare_complex_list([dict(baz=1, bar=2)], [dict(foo=1)])
        res4 = compare_complex_list([dict(baz=1, bar=2)], [dict(baz=1, bar=2)])

        assert res1 is None and res2 is None and res4 is None
        assert res3 == [dict(baz=1, bar=2)]

    def test_compare_dictionary(self):
        res1 = compare_dictionary({}, None)
        res2 = compare_dictionary(None, dict(foo=1))
        res3 = compare_dictionary(dict(baz=1, bar=2), dict(foo=1))
        res4 = compare_dictionary(dict(baz=1, bar=2), dict(baz=1, bar=2))

        assert res1 is None and res2 is None and res4 is None
        assert res3 == dict(baz=1, bar=2)

    def test_nested_diff(self):
        res1 = nested_diff(dict(foo=1), None, [])
        res2 = nested_diff(None, dict(foo=1), [])
        res3 = nested_diff(dict(foo=dict(baz=1, bar=2)), dict(baz=1), ['bar'])
        res4 = nested_diff(dict(foo=dict(baz=1, bar=2)), dict(foo=dict(baz=2, bar=3)), ['bar'])
        res5 = nested_diff(dict(foo=dict(baz=1, bar=2)), dict(foo=dict(baz=1, bar=3)), ['bar'])

        assert res1 is True and res3 is True and res4 is True
        assert res2 is False and res5 is False
