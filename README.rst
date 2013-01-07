requests-ntlm
=============

This package allows for HTTP NTLM authentication using the requests library.

Usage
-----

``HttpNtlmAuth`` extends requests ``AuthBase``, so usage is simple:

.. code:: python

    import requests
    from requests_ntlm import HttpNtlmAuth

    requests.get("http://ntlm_protected_site.com",auth=HttpNtlmAuth('domain\\username','password'))

Installation
------------

The package hasn't been uploaded to pip yet, but it can be installed by 
running::

    sudo python ./setup.py install

Requirements
------------

- requests_
- python-ntlm_

.. _requests: https://github.com/kennethreitz/requests/
.. _python-ntlm: http://code.google.com/p/python-ntlm/

Authors
-------

- `Ben Toews`_

.. _Ben Toews: https://github.com/mastahyeti

- `Ian Cordasco`_

.. _Ian Cordasco: https://github.com/sigmavirus24

- `Cory Benfield`_

.. _Cory Benfield: https://github.com/Lukasa
