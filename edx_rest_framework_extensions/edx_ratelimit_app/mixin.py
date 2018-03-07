import logging
from ratelimit.utils import is_ratelimited
from django.http import JsonResponse
from edx_rest_framework_extensions.edx_ratelimit_app.utils import (
    get_whitelist_rate,
    get_ratelimit_conf,
    RATELIMIT_DEFAULTS
)
logger = logging.getLogger(__name__)


class EdxRateLimitMixin(object):

    # had to be configured via db model
    ip_whitelist = {}

    ratelimit_group = RATELIMIT_DEFAULTS['group']
    ratelimit_key = RATELIMIT_DEFAULTS['key']
    ratelimit_rate = RATELIMIT_DEFAULTS['rate']
    ratelimit_block = RATELIMIT_DEFAULTS['block']
    ratelimit_methods = RATELIMIT_DEFAULTS['methods']

    @classmethod
    def setup_edx_ratelimit_config(cls):
        # Ensures that the ratelimit_key is called as a function instead
        # of a method if it is a callable (ie self is not passed).
        if callable(cls.ratelimit_key):
            cls.ratelimit_key = cls.ratelimit_key.__func__

        # if configuration is available pick from db, or resort to class default
        conf = get_ratelimit_conf()

        if conf:
            cls.ratelimit_rate = conf['rate']
            cls.ratelimit_block = bool(conf['block'])
            cls.ratelimit_methods = conf['methods']
            cls.ip_whitelist = conf['ip_whitelist']

    def get_ratelimit_rate(cls, request):
        whitelist_rate = get_whitelist_rate(request,
                                            cls.ratelimit_key,
                                            cls.ratelimit_group,
                                            cls.ip_whitelist)
        rate = whitelist_rate if whitelist_rate else cls.ratelimit_rate
        return rate

    def dispatch(self, *args, **kwargs):

        request = args[0]
        self.setup_edx_ratelimit_config()
        request.limited = getattr(request, 'limited', False)
        rate = self.get_ratelimit_rate(request)

        ratelimited = is_ratelimited(request=request,
                                     group=self.ratelimit_group,
                                     fn=super(EdxRateLimitMixin, self).dispatch,
                                     key=self.ratelimit_key,
                                     rate=rate,
                                     method=self.ratelimit_methods,
                                     increment=True)
        if ratelimited and self.ratelimit_block:
            # add log to splunk
            logger.exception('Too many request: Ratelimit of {} exceeded'.format(
                self.ratelimit_rate))

            # todo: add log to NR
            return JsonResponse(data={
                'message': 'Too many request: Ratelimit of {} exceeded'.
                format(self.ratelimit_rate),
                'status': False
            }, status=429)
        return super(EdxRateLimitMixin, self).dispatch(*args, **kwargs)
