#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name='edx-drf-extensions',
    version='0.1.0',
    description='edX extensions of Django REST Framework',
    author='edX',
    url='https://github.com/edx/edx-drf-extensions',
    license='AGPL',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    packages=['edx_rest_framework_extensions'],
    install_requires=[
        'djangorestframework>=3.2.3,<4.0.0',
    ]
)
