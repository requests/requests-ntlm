# requests_ntlm

This package allows for HTTP NTLM authentication using the requests library.

## Usage

`HttpNtlmAuth` extends requests `AuthBase`, so usage is simple:

```python
import requests
from requests_ntlm import HttpNtlmAuth

requests.get("http://ntlm_protected_site.com",auth=HttpNtlmAuth('domain\\username','password'))
```

## Installation

The package hasn't been uploaded to pip yet, but it can be installed by running:

    sudo python ./setup.py install

## Requirements

- [`requests`](https://github.com/kennethreitz/requests/)
- [`python-ntlm`](http://code.google.com/p/python-ntlm/)

## Authors

- [Ben Toews](https://github.com/mastahyeti)