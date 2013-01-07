#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name     = 'requests_ntlm',
    version  = '0.0.2',
    packages = [ 'requests_ntlm' ],
    requires = [ 'requests(>=1.0.0)', 'ntlm' ],
    provides = [ 'requests_ntlm' ]
)