from binascii import unhexlify

# Default variables used for the ntlm_context
username = 'username'
domain = 'domain'
password = 'password'

timestamp = unhexlify('0000000000000000')
client_challenge = unhexlify('aaaaaaaaaaaaaaaa')
session_base_key = unhexlify('55555555555555555555555555555555')

# Used in the client challenge, we want to return hex aa for the length as per Microsoft's example
def mock_random(ignore):
    return client_challenge

# Used to mock out the exported_session_key in the authenticate messages
def mock_random_session_key():
    return session_base_key

# Used to mock out the timestamp value as per Microsoft's example
def mock_timestamp():
    return timestamp

# Used to mock out the version value as per Microsoft's example (calculated manually)
def mock_version(ignore):
    return unhexlify('0501280a0000000f')