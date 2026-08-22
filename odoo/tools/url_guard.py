# Part of Odoo. See LICENSE file for full copyright and licensing details.
"""SSRF egress guard for server-side fetches of user-supplied URLs.

Restricts outbound requests to the `http`/`https` schemes and to
publicly-routable target addresses, re-validating after every redirect hop.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests

DEFAULT_MAX_REDIRECTS = 5


class UnsafeUrlError(ValueError):
    """Raised when a URL is unsafe to fetch server-side (bad scheme or a
    non-public target address)."""


def validate_public_url(url):
    """Validate the scheme and the resolved address(es) of `url`.

    :raise UnsafeUrlError: if the scheme is not http/https or the host resolves
        to a loopback/private/link-local/reserved/multicast/unspecified address.
    :return: `url` unchanged when it is considered safe.
    """
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise UnsafeUrlError("Disallowed URL scheme: %r" % (url,))
    host = parts.hostname
    if not host:
        raise UnsafeUrlError("URL has no host: %r" % (url,))
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    try:
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError("Cannot resolve host %r" % (host,)) from exc
    for *_, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeUrlError("URL resolves to non-public address %s: %r" % (ip, url))
    return url


def guarded_request(method, url, *, session=None, max_redirects=DEFAULT_MAX_REDIRECTS, **kwargs):
    """Perform `method` on `url` with per-hop SSRF validation.

    Redirects are followed manually so that every hop is re-validated; any
    `allow_redirects` supplied by the caller is ignored.
    """
    sess = session or requests
    kwargs.pop('allow_redirects', None)
    current = url
    for _hop in range(max_redirects + 1):
        validate_public_url(current)
        # Dispatch through the named method (`get`/`head`) rather than
        # `request` so existing call sites and their test mocks keep working.
        http_method = getattr(sess, method.lower())
        response = http_method(current, allow_redirects=False, **kwargs)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get('Location')
            if not location:
                return response
            current = urljoin(current, location)
            continue
        return response
    raise UnsafeUrlError("Too many redirects while fetching %r" % (url,))


def guarded_get(url, **kwargs):
    return guarded_request('GET', url, **kwargs)


def guarded_head(url, **kwargs):
    return guarded_request('HEAD', url, **kwargs)
