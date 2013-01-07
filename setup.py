#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

with open('LICENSE','r') as f:
  license = f.read().strip()

setup(
    name         = 'requests_ntlm',
    version      = '0.0.2.1',
    packages     = [ 'requests_ntlm' ],
    requires     = [ 'requests(>=1.0.0)', 'ntlm' ],
    provides     = [ 'requests_ntlm' ],
    author       = 'Ben Toews',
    author_email = 'mastahyeti@gmail.com',
    description  = 'This package allows for HTTP NTLM authentication using the requests library.',
    license      = license
)
