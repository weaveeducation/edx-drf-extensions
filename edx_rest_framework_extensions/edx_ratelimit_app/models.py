# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from jsonfield.fields import JSONField
from config_models.models import ConfigurationModel


class EdxRateLimitConfiguration(ConfigurationModel):
    SECONDS = '/sec'
    MINUTES = '/minute'
    HOUR = '/hour'
    DAY = '/day'

    RATE_TIME_WINDOW_CHOICES = (
        (SECONDS, '/sec'),
        (MINUTES, '/minute'),
        (HOUR, '/hour'),
        (DAY, '/day')
    )

    time_window_duration = models.CharField(
        max_length=20,
        default='5/m',
        choices=RATE_TIME_WINDOW_CHOICES,
        blank=False,
        help_text="Time window used for request frequency",
        verbose_name="Time Window"

    )
    request_frequency = models.PositiveIntegerField(
        default=5,
        blank=False,
        help_text="The request frequency limit at which view is throttled.",
        verbose_name="Request Frequency"
    )
    block = models.BooleanField(
        default=False,
        blank=True,
        help_text="Should the view be blocked if rate limit threshold is reached.",
        verbose_name="Block View"
    )
    methods = models.TextField(
        default='ALL',
        blank=True,
        help_text="Rate limit on what http methods. eg GET, POST, PUT or ALL",
        verbose_name="HTTP Methods"
    )
    ip_whitelist = JSONField(
        default={},
        blank=True,
        help_text="""IP list with edx_ratelimit configuration. Its a Json with IP->Rate mapping.
         eg
         {
          "127.0.0.102":"300/m",
          "127.0.0.100":"100/m",
          "127.0.0.101":"200/m",
          "127.0.0.1":"3/m"
        }
        """,
        verbose_name="IP Whitelist"
    )


