#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='requests_ntlm',
    version='0.3.0',
    packages=[ 'requests_ntlm' ],
    install_requires=[ 'requests>=2.0.0', 'ntlm-auth>=1.0.2' ],
    provides=[ 'requests_ntlm' ],
    author='Ben Toews',
    author_email='mastahyeti@gmail.com',
    url='https://github.com/requests/requests-ntlm',
    description='This package allows for HTTP NTLM authentication using the requests library.',
    license='ISC',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'License :: OSI Approved :: ISC License (ISCL)',
    ],
)
