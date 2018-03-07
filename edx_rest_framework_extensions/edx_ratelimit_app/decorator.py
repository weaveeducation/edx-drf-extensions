import logging
from functools import wraps
from django.http import HttpRequest, JsonResponse
from ratelimit import ALL
from ratelimit.utils import is_ratelimited
from edx_rest_framework_extensions.edx_ratelimit_app.utils import (
    get_whitelist_rate,
    get_ratelimit_conf,
    RATELIMIT_DEFAULTS
)
logger = logging.getLogger(__name__)


def edxratelimit(decorated_rate=None, group=None, key=None):

    def decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kw):
            # Work as a CBV method decorator.
            if isinstance(args[0], HttpRequest):
                request = args[0]
            else:
                request = args[1]
            request.limited = getattr(request, 'limited', False)

            conf = get_ratelimit_conf()
            if conf:
                ip_whitelist_rate = get_whitelist_rate(request, key, group, conf['ip_whitelist'])
                conf_rate = ip_whitelist_rate if ip_whitelist_rate else conf['rate']
                rate = conf_rate
            else:
                rate = decorated_rate if decorated_rate else RATELIMIT_DEFAULTS['rate']

            block = conf['block'] if conf and conf['block'] else True
            method = conf['methods'] if conf and conf['methods'] else ALL

            ratelimited = is_ratelimited(request=request, group=group, fn=fn,
                                         key=key, rate=rate, method=method,
                                         increment=True)
            if ratelimited and block:
                logger.exception('Too many request: Ratelimit of {} exceeded'.format(rate))
                # todo: add log to NR
                return JsonResponse(data={
                    'message': 'Too many request: Ratelimit of {} exceeded'.format(rate),
                    'status': False
                }, status=429)
            return fn(*args, **kw)
        return _wrapped
    return decorator

