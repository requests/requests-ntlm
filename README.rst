requests-ntlm
=============

.. image:: https://travis-ci.org/requests/requests-ntlm.svg?branch=master
    :target: https://travis-ci.org/requests/requests-ntlm

.. image:: https://coveralls.io/repos/github/requests/requests-ntlm/badge.svg?branch=master
    :target: https://coveralls.io/github/requests/requests-ntlm?branch=master

This package allows for HTTP NTLM authentication using the requests library.

Usage
-----

``HttpNtlmAuth`` extends requests ``AuthBase``, so usage is simple:

.. code:: python

    import requests
    from requests_ntlm import HttpNtlmAuth

    requests.get("http://ntlm_protected_site.com",auth=HttpNtlmAuth('domain\\username','password'))
    
``HttpNtlmAuth`` can be used in conjunction with a ``Session`` in order to
make use of connection pooling. Since NTLM authenticates connections,
this is more efficient. Otherwise, each request will go through a new
NTLM challenge-response.

.. code:: python

    import requests
    from requests_ntlm import HttpNtlmAuth

    session = requests.Session()
    session.auth = HttpNtlmAuth('domain\\username','password')
    session.get('http://ntlm_protected_site.com')

Installation
------------

    pip install requests_ntlm

Requirements
------------

- requests_
- ntlm-auth_

.. _requests: https://github.com/kennethreitz/requests/
.. _ntlm-auth: https://github.com/jborean93/ntlm-auth

Authors
-------

- `Ben Toews`_

.. _Ben Toews: https://github.com/mastahyeti

- `Ian Cordasco`_

.. _Ian Cordasco: https://github.com/sigmavirus24

- `Cory Benfield`_

.. _Cory Benfield: https://github.com/Lukasa
