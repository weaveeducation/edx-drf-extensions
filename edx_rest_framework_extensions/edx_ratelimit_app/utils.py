# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from ipware.ip import get_ip
from .models import EdxRateLimitConfiguration
from importlib import import_module

ALL = (None,)

# Used when no db configuration is available for rate limit
RATELIMIT_DEFAULTS = {
    'rate' :            '5/m',
    'block':            True,
    'methods':          ALL,
    'ip_whitelist':     {},
    'group':            None,
    # callable function real_ip return value is used as key
    'key':              'edx_rest_framework_extensions.edx_ratelimit_app.utils.real_ip'
}


def real_ip(group, request):
    return get_ip(request)


def get_ratelimit_conf():
    conf = EdxRateLimitConfiguration.objects.all().first()
    if conf:
        if conf.request_frequency:
            rate = str(conf.request_frequency) + conf.time_window_duration
        else:
            rate = RATELIMIT_DEFAULTS['rate']
        block = bool(conf.block)
        ip_whitelist = conf.ip_whitelist if conf.ip_whitelist else RATELIMIT_DEFAULTS['ip_whitelist']

        methods = conf.methods.split(',') if conf.methods else RATELIMIT_DEFAULTS['methods']
        methods = ALL if 'ALL' in methods else methods

        return {
            'rate': rate,
            'block': block,
            'methods': methods,
            'ip_whitelist': ip_whitelist
        }
    return None


def get_whitelist_rate(request, key, group, ip_whitelist):
    ip = None
    if callable(key):  # direct function call to get key
        ip = key(group=group, request=request)
    elif '.' in key:  # path of the function inside some package
        mod, attr = key.rsplit('.', 1)
        keyfn = getattr(import_module(mod), attr)
        ip = keyfn(group, request)

    # get whitelist rate if applicable or resort to db configured rate
    if ip in ip_whitelist:
        return ip_whitelist[ip]
    else:
        return None
