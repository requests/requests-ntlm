#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name="requests_ntlm",
    version="1.2.0",
    packages=["requests_ntlm"],
    install_requires=["requests>=2.0.0", "ntlm-auth>=1.0.2", "cryptography>=1.3"],
    python_requires=">=3.7",
    provides=["requests_ntlm"],
    author="Ben Toews",
    author_email="mastahyeti@gmail.com",
    url="https://github.com/requests/requests-ntlm",
    description="This package allows for HTTP NTLM authentication using the requests library.",
    license="ISC",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)
