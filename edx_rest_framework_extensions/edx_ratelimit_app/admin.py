# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import EdxRateLimitConfiguration


class EdxRateLimitAdmin(admin.ModelAdmin):
    fields = ('request_frequency', 'time_window_duration', 'block', 'methods', 'ip_whitelist')

admin.site.register(EdxRateLimitConfiguration, EdxRateLimitAdmin)
