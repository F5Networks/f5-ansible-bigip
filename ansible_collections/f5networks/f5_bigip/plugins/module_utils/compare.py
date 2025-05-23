# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.six import iteritems


def cmp_simple_list(want, have, cmp_order=False):
    if want is None:
        return None
    if have is None and want in ['', 'none']:
        return None
    if have is not None and want in ['', 'none']:
        return []
    if have is None:
        return want
    if cmp_order:
        if set(want) == set(have):
            if want != have:
                return want
    if set(want) != set(have):
        return want
    return None


def cmp_str_with_none(want, have):
    if want is None:
        return None
    if have is None and want == '':
        return None
    if want != have:
        return want


def recursive_sort(element):
    if isinstance(element, list):
        return [recursive_sort(item) for item in element]
    elif isinstance(element, tuple):
        return tuple(recursive_sort(item) for item in element)
    elif isinstance(element, dict):
        return {key: recursive_sort(value) for key, value in sorted(element.items())}
    else:
        return element


def compare_complex_list(want, have):
    """Performs a complex list comparison

    A complex list is a list of dictionaries

    Args:
        want (list): List of dictionaries to compare with second parameter.
        have (list): List of dictionaries compare with first parameter.

    Returns:
        bool:
    """
    if want == [] and have is None:
        return None
    if want is None:
        return None
    if have is None:
        return want
    w = []
    h = []
    for x in want:
        tmp = [(str(k), str(recursive_sort(v))) for k, v in iteritems(x)]
        w += tmp
    for x in have:
        tmp = [(str(k), str(recursive_sort(v))) for k, v in iteritems(x)]
        h += tmp
    if set(w) == set(h):
        return None
    else:
        return want


def compare_dictionary(want, have):
    """Performs a dictionary comparison

    Args:
        want (dict): Dictionary to compare with second parameter.
        have (dict): Dictionary to compare with first parameter.

    Returns:
        bool:
    """
    if want == {} and have is None:
        return None
    if want is None:
        return None
    if have is None:
        return want
    w = [(str(k), str(v)) for k, v in iteritems(want)]
    h = [(str(k), str(v)) for k, v in iteritems(have)]
    if set(w) == set(h):
        return None
    else:
        return want


def compare_key_values(want, have):
    if want is None:
        return None
    if have is None:
        return want
    for k, v in have.items():
        if k not in want.keys():
            continue
        if want[k] != have[k]:
            return want
    return None


def nested_diff(want, have, invalid):
    """ Performs any() type operation on nested dictionaries

        Args:
            want (dict): Dictionary to compare with second parameter.
            have (dict): Dictionary to compare with first parameter.
            invalid (list): List of keys to be ignored when comparing.

        Returns:
            bool:

    """
    if have is None:
        return True
    if want is None:
        return False
    for k in want:
        if k not in have:
            return True
        else:
            if isinstance(want[k], dict):
                if nested_diff(want[k], have[k], invalid):
                    return True
            else:
                if k in invalid:
                    continue
                if want[k] != have[k]:
                    return True
    return False
