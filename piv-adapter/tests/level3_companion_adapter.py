#!/usr/bin/env python3
"""Software-only fake PIV backend for Java/Rust companion interoperability.

The fixture uses synthetic DER keys and serial 123456. This script never imports
PKCS#11 or discovers a card. Private DER paths are allowed ONLY in these generated
test fixtures; production companion operations keep recovered PQ seeds in memory.
"""
import base64
import os
import pathlib
import subprocess
import sys
import tempfile
root = pathlib.Path(__file__).resolve().parent
assert os.environ.get('PKCS11_SERIAL') == '123456'
assert os.environ.get('PQMAIL_LEVEL3_POLYFILL') == '1'
algorithm = sys.stdin.buffer.readline().strip().decode('ascii')
public = base64.b64decode(sys.stdin.buffer.readline().strip(), validate=True)
payload = base64.b64decode(sys.stdin.buffer.readline().strip(), validate=True)
pin = bytearray(sys.stdin.buffer.readline().strip())
try:
    assert pin == b'123456'
    slot = {'Ed25519':'9c', 'X25519':'9d', 'ECDH-P384':'83'}[algorithm]
    expected = 'PKCS11_TRADITIONAL_SLOT' if algorithm == 'Ed25519' else 'PKCS11_ECDH_SLOT'
    assert os.environ[expected] == slot
    assert not any(name in os.environ for name in ['PQMAIL_CERTIFICATION_SLOTS','PQMAIL_OPENPGP_COMPATIBILITY','PQMAIL_POLYFILL_CERTIFICATION'])
    assert public == (root/(slot+'.der')).read_bytes()
    with (root/'software-operations.log').open('a') as log:
        log.write(algorithm+' slot '+slot+'\n')
    openssl = os.environ['OPENSSL_BIN']
    with tempfile.TemporaryDirectory() as temporary:
        incoming = pathlib.Path(temporary)/'public-input'
        incoming.write_bytes(payload)
        args = [openssl,'pkeyutl','-inkey',str(root/(slot+'-test-private.der')),'-keyform','DER']
        if algorithm == 'Ed25519':
            args += ['-sign','-rawin','-in',str(incoming)]
        else:
            args += ['-derive','-peerkey',str(incoming),'-peerform','DER']
        result = subprocess.check_output(args,stderr=subprocess.PIPE)
    if algorithm == 'Ed25519':
        result = base64.b64encode(result)+b'\n'
    sys.stdout.buffer.write(result)
finally:
    pin[:] = b'\0'*len(pin)
