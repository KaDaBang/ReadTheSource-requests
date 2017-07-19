# -*- coding: utf-8 -*-

"""
requests.cookies
~~~~~~~~~~~~~~~~

Compatibility code to be able to use `cookielib.CookieJar` with requests.

requests.utils imports from here, so be careful with imports.
"""

import copy
import time
import calendar
import collections

from ._internal_utils import to_native_string
from .compat import cookielib, urlparse, urlunparse, Morsel

try:
    import threading
except ImportError:
    import dummy_threading as threading


class MockRequest(object):
    """Wraps a `requests.Request` to mimic a `urllib2.Request`.

    The code in `cookielib.CookieJar` expects this interface in order to correctly
    manage cookie policies, i.e., determine whether a cookie can be set, given the
    domains of the request and the cookie.

    The original request object is read-only. The client is responsible for collecting
    the new headers via `get_new_headers()` and interpreting them appropriately. You
    probably want `get_cookie_header`, defined below.
    """

    def __init__(self, request):
        self._r = request
        self._new_headers = {}
        self.type = urlparse(self._r.url).scheme

    def get_type(self):
        return self.type

    def get_host(self):
        return urlparse(self._r.url).netloc

    def get_origin_req_host(self):
        return self.get_host()

    def get_full_url(self):
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self._r.headers.get('Host'):
            return self._r.url
        # If they did set it, retrieve it and reconstruct the expected domain
        host = to_native_string(self._r.headers['Host'], encoding='utf-8')
        parsed = urlparse(self._r.url)
        # Reconstruct the URL as we expect it
        return urlunparse([
            parsed.scheme, host, parsed.path, parsed.params, parsed.query,
            parsed.fragment
        ])

    def is_unverifiable(self):
        return True

    def has_header(self, name):
        return name in self._r.headers or name in self._new_headers

    def get_header(self, name, default=None):
        return self._r.headers.get(name, self._new_headers.get(name, default))

    def add_header(self, key, val):
        """cookielib has no legitimate use for this method; add it back if you find one."""
        raise NotImplementedError("Cookie headers should be added with add_unredirected_header()")

    def add_unredirected_header(self, name, value):
        self._new_headers[name] = value

    def get_new_headers(self):
        return self._new_headers

    @property
    def unverifiable(self):
        return self.is_unverifiable()

    @property
    def origin_req_host(self):
        return self.get_origin_req_host()

    @property
    def host(self):
        return self.get_host()


class MockResponse(object):
    """Wraps a `httplib.HTTPMessage` to mimic a `urllib.addinfourl`.

    ...what? Basically, expose the parsed HTTP headers from the server response
    the way `cookielib` expects to see them.
    """

    def __init__(self, headers):
        """Make a MockResponse for `cookielib` to read.

        :param headers: a httplib.HTTPMessage or analogous carrying the headers
        """
        self._headers = headers

    def info(self):
        return self._headers

    def getheaders(self, name):
        self._headers.getheaders(name)


def extract_cookies_to_jar(jar, request, response):
    """Extract the cookies from the response into a CookieJar.

    :param jar: cookielib.CookieJar (not necessarily a RequestsCookieJar)
    :param request: our own requests.Request object
    :param response: urllib3.HTTPResponse object
    """
    if not (hasattr(response, '_original_response') and
            response._original_response):
        return
    # the _original_response field is the wrapped httplib.HTTPResponse object,
    req = MockRequest(request)
    # pull out the HTTPMessage with the headers and put it in the mock:
    res = MockResponse(response._original_response.msg)
    jar.extract_cookies(res, req)


def get_cookie_header(jar, request):
    """
    Produce an appropriate Cookie header string to be sent with `request`, or None.

    :rtype: str
    """
    r = MockRequest(request)
    jar.add_cookie_header(r)
    return r.get_new_headers().get('Cookie')


def remove_cookie_by_name(cookiejar, name, domain=None, path=None):
    """通过cookie的名字来移除cookie，默认情况下覆盖所有域名和路径

    Wraps CookieJar.clear(), is O(n).
    """
    clearables = []
    for cookie in cookiejar:
        if cookie.name != name:
            continue
        if domain is not None and domain != cookie.domain:
            continue
        if path is not None and path != cookie.path:
            continue
        clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


class CookieConflictError(RuntimeError):
    """There are two cookies that meet the criteria specified in the cookie jar.
    Use .get and .set and include domain and path args in order to be more specific.
    """


class RequestsCookieJar(cookielib.CookieJar, collections.MutableMapping):
    """兼容类，是个CookieJar，但表示方式为dict

    由于一些客户端可能期望使用response.cookies和session.cookies来支持字典操作，
    所以在不为requests和sessions制定cookjar的情况下，我们将默认使用此类

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Requests不会使用自带的字典接口，这样是为了兼容外部的客户端代码。所有的代码应该在外部提供的CookieJar外工作，
    如LWPCookieJar、FileCookieJar

    Requests does not use the dict interface internally; it's just for
    compatibility with external client code. All requests code should work
    out of the box with externally provided instances of ``CookieJar``, e.g.
    ``LWPCookieJar`` and ``FileCookieJar``.

    与常规的CookieJar不同，这个类是可pickle的
    Unlike a regular CookieJar, this class is pickleable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
    """

    def get(self, name, default=None, domain=None, path=None):
        """
        dict-like 的get()也支持可选的domain和path参数，以此解决在多域名中使用单个cookiejar的命名冲突

        .. warning:: operation is O(n), not O(1).
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        """Dict-like 的set()也支持可选的domain和path参数，以此解决在多域名中使用单个cookiejar的命名冲突
        """
        # 支持客户端代码使用为value赋值None来删除cookie
        if value is None:
            remove_cookie_by_name(self, name, domain=kwargs.get('domain'), path=kwargs.get('path'))
            return

        if isinstance(value, Morsel):
            # 将morsel对象转为cookie
            c = morsel_to_cookie(value)
        else:
            # 根据传入name和value创建cookie
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self):
        """
        Dict-like 的iterkeys() ,返回一个cookie名字的迭代器

        .. seealso:: itervalues() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self):
        """Dict-like 的keys() 返回一个cookie名字的列表
        jar.

        .. seealso:: values() and items().
        """
        return list(self.iterkeys())

    def itervalues(self):
        """Dict-like 的iterkeys() 返回一个cookie的迭代器
        from the jar.

        .. seealso:: iterkeys() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self):
        """Dict-like values() 返回一个值的列表

        .. seealso:: keys() and items().
        """
        return list(self.itervalues())

    def iteritems(self):
        """Dict-like iteritems() 返回一个键值对元组的迭代器

        .. seealso:: iterkeys() and itervalues().
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self):
        """Dict-like items() 返回一个键值对元组的列表,
        允许调用dict(RequestsCookieJar)来获得普通python的键值对字典

        .. seealso:: keys() and values().
        """
        return list(self.iteritems())

    def list_domains(self):
        """获得jar中所有域名的列表"""
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self):
        """获得jar中所有路径"""
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self):
        """如果jar中有多个域名返回True，反之返回False

        :rtype: bool
        """
        domains = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(self, domain=None, path=None):
        """
        获得一个普通的python字典

        :rtype: dict
        """
        dictionary = {}
        for cookie in iter(self):
            if (
                (domain is None or cookie.domain == domain) and
                (path is None or cookie.path == path)
            ):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __contains__(self, name):
        try:
            return super(RequestsCookieJar, self).__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name):
        """Dict-like __getitem__()用于兼容客户代码的魔法方法
        如果单个name有多个cookie，抛出异常，这种情况下，使用更加显示的get()方法

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name, value):
        """Dict-like __setitem__ 用于兼容客户代码
        如果一个name下有了cookie，将抛出异常，在这种情况下，使用更加明确的set()方法
        """
        self.set(name, value)

    def __delitem__(self, name):
        """Deletes a cookie given a name. Wraps ``cookielib.CookieJar``'s
        ``remove_cookie_by_name()``.
        """
        remove_cookie_by_name(self, name)

    def set_cookie(self, cookie, *args, **kwargs):
        if hasattr(cookie.value, 'startswith') and cookie.value.startswith('"') and cookie.value.endswith('"'):
            cookie.value = cookie.value.replace('\\"', '')
        return super(RequestsCookieJar, self).set_cookie(cookie, *args, **kwargs)

    def update(self, other):
        """Updates this jar with cookies from another CookieJar or dict-like"""
        if isinstance(other, cookielib.CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))
        else:
            super(RequestsCookieJar, self).update(other)

    def _find(self, name, domain=None, path=None):
        """Requests uses this method internally to get cookie values.

        If there are conflicting cookies, _find arbitrarily chooses one.
        See _find_no_duplicates if you want an exception thrown if there are
        conflicting cookies.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :return: cookie.value
        """
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

    def _find_no_duplicates(self, name, domain=None, path=None):
        """
        __get_item__和get调用此函数，该函数不会用于Requests中其他地方

        :param name: 包含cookie名字的字符串
        :param domain: (可选) 包含cookie域名的字符串
        :param path: (optional) 包含路径的字符串
        :raises KeyError: 若找不到cookie
        :raises CookieConflictError: 如果有多个cookie匹配名字和可选域名、路径
        :return: cookie.value
        """
        toReturn = None
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if toReturn is not None:  # if there are multiple cookies that meet passed in criteria
                            raise CookieConflictError('There are multiple cookies with name, %r' % (name))
                        toReturn = cookie.value  # we will eventually return this as long as no cookie conflict

        if toReturn:
            return toReturn
        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

    def __getstate__(self):
        """Unlike a normal CookieJar, this class is pickleable."""
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop('_cookies_lock')
        return state

    def __setstate__(self, state):
        """Unlike a normal CookieJar, this class is pickleable."""
        self.__dict__.update(state)
        if '_cookies_lock' not in self.__dict__:
            self._cookies_lock = threading.RLock()

    def copy(self):
        """Return a copy of this RequestsCookieJar."""
        new_cj = RequestsCookieJar()
        new_cj.update(self)
        return new_cj


def _copy_cookie_jar(jar):
    if jar is None:
        return None

    if hasattr(jar, 'copy'):
        # We're dealing with an instance of RequestsCookieJar
        return jar.copy()
    # We're dealing with a generic CookieJar instance
    new_jar = copy.copy(jar)
    new_jar.clear()
    for cookie in jar:
        new_jar.set_cookie(copy.copy(cookie))
    return new_jar


def create_cookie(name, value, **kwargs):
    """
    使用未知名的参数建立cookie
    默认情况下，name和value将会被分配到空域名''下，并且发送到每一个请求（此cookie被称为supercookie）
    """
    result = dict(
        version=0,
        name=name,
        value=value,
        port=None,
        domain='',          # 可将cookie限制在特定的域中，若没有制定域，就默认产生set-cookie响应的服务器主机名
        path='/',           # 通过这个属性可以为服务器上特定的文档分配cookie
        secure=False,       # 若为True，只在HTTP使用SSL时才会发送Cookie
        expires=None,       # 日期字符串, 过期时间
        discard=True,       # True为会话cookie，会话结束后（关闭浏览器），cookie便被删除
        comment=None,
        comment_url=None,
        rest={'HttpOnly': None},
        rfc2109=False,      # False：cookie版本为0， True：cookie版本为1
    )

    # 若有多余的参数， 则抛出异常
    badargs = set(kwargs) - set(result)
    if badargs:
        err = 'create_cookie() got unexpected keyword arguments: %s'
        raise TypeError(err % list(badargs))

    # 将传入参数映射到cookie字典中
    result.update(kwargs)
    result['port_specified'] = bool(result['port'])
    result['domain_specified'] = bool(result['domain'])
    result['domain_initial_dot'] = result['domain'].startswith('.')
    result['path_specified'] = bool(result['path'])

    return cookielib.Cookie(**result)


def morsel_to_cookie(morsel):
    """将Morsel类(cookie中每一项数据的属性的抽象类)转换为python的dict键值对形式"""

    expires = None
    if morsel['max-age']:
        try:
            expires = int(time.time() + int(morsel['max-age']))
        except ValueError:
            raise TypeError('max-age: %s must be integer' % morsel['max-age'])
    elif morsel['expires']:
        time_template = '%a, %d-%b-%Y %H:%M:%S GMT'
        expires = calendar.timegm(
            time.strptime(morsel['expires'], time_template)
        )
    return create_cookie(
        comment=morsel['comment'],
        comment_url=bool(morsel['comment']),
        discard=False,
        domain=morsel['domain'],
        expires=expires,
        name=morsel.key,
        path=morsel['path'],
        port=None,
        rest={'HttpOnly': morsel['httponly']},
        rfc2109=False,
        secure=bool(morsel['secure']),
        value=morsel.value,
        version=morsel['version'] or 0,
    )


def cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True):
    """
    利用传入的cookie_dict构造CookieJar类

    :param cookie_dict: 插入CookieJar的键值对
    :param cookiejar: (optional) 加入到cookies的cookiejar
    :param overwrite: (optional) 若为False，则不会用新的cookies代替已经存在jar中的cookies
    """
    if cookiejar is None:
        cookiejar = RequestsCookieJar()

    if cookie_dict is not None:
        names_from_jar = [cookie.name for cookie in cookiejar]
        for name in cookie_dict:
            if overwrite or (name not in names_from_jar):
                cookiejar.set_cookie(create_cookie(name, cookie_dict[name]))

    return cookiejar


def merge_cookies(cookiejar, cookies):
    """Add cookies to cookiejar and returns a merged CookieJar.

    :param cookiejar: CookieJar object to add the cookies to.
    :param cookies: Dictionary or CookieJar object to be added.
    """
    if not isinstance(cookiejar, cookielib.CookieJar):
        raise ValueError('You can only merge into CookieJar')

    if isinstance(cookies, dict):
        cookiejar = cookiejar_from_dict(
            cookies, cookiejar=cookiejar, overwrite=False)
    elif isinstance(cookies, cookielib.CookieJar):
        try:
            cookiejar.update(cookies)
        except AttributeError:
            for cookie_in_jar in cookies:
                cookiejar.set_cookie(cookie_in_jar)

    return cookiejar
