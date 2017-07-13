# -*- coding: utf-8 -*-

"""
requests._internal_utils
~~~~~~~~~~~~~~

提供Requests内部使用的工具函数，这些函数很少使用第三方依赖
Provides utility functions that are consumed internally by Requests
which depend on extremely few external helpers (such as compat)
"""

from .compat import is_py2, builtin_str, str


def to_native_string(string, encoding='ascii'):
    """
    不管传入的string类型为何，均返回一个原生的string类型字符串
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        if is_py2:
            out = string.encode(encoding)
        else:
            out = string.decode(encoding)

    return out


def unicode_is_ascii(u_string):
    """确定unicode字符串是否为ascii字符

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False
