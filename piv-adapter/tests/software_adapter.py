#!/usr/bin/env python3
"""TEST ONLY: genuine OpenSSL crypto behind the production pipe protocol.

All private keys here are freshly generated synthetic test fixtures in a
temporary directory. This script never imports PKCS#11 or accesses a device.
It independently tests the Rust adapter's SPKI, external-mu, and KEM framing.
"""
import base64
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent
openssl = (root / "openssl-path").read_text()
algorithm = sys.stdin.buffer.readline().strip().decode("ascii")
public = base64.b64decode(sys.stdin.buffer.readline().rstrip(b"\n"), validate=True)
payload = base64.b64decode(sys.stdin.buffer.readline().rstrip(b"\n"), validate=True)
pin = bytearray(sys.stdin.buffer.readline().rstrip(b"\n"))
try:
    # This is a fixed synthetic PIN, never a user's PIN. Assertions prove the
    # wire protocol delivered it through stdin and did not mix it into payload.
    assert pin == b"123456"
    key = root / (algorithm + ".pem")
    actual = subprocess.check_output([openssl, "pkey", "-in", str(key),
                                     "-pubout", "-outform", "DER"], stderr=subprocess.PIPE)
    assert actual == public, "Public key mismatch"
    with tempfile.TemporaryDirectory() as d:
        incoming = pathlib.Path(d) / "input"
        incoming.write_bytes(payload)
        args = [openssl, "pkeyutl", "-inkey", str(key)]
        if algorithm == "ML-DSA-65":
            # OpenSSL independently consumes external mu, while Sequoia later
            # verifies against the original message digest in ordinary mode.
            args += ["-sign", "-pkeyopt", "mu:1", "-in", str(incoming)]
        elif algorithm == "Ed25519":
            args += ["-sign", "-rawin", "-in", str(incoming)]
        elif algorithm == "ML-KEM-768":
            args += ["-decap", "-in", str(incoming)]
        elif algorithm == "X25519":
            args += ["-derive", "-peerkey", str(incoming), "-peerform", "DER"]
        else:
            raise ValueError("Unexpected test operation")
        result = subprocess.check_output(args, stderr=subprocess.PIPE)
    if algorithm in ("ML-DSA-65", "Ed25519"):
        result = base64.b64encode(result) + b"\n"
    sys.stdout.buffer.write(result)
finally:
    pin[:] = b"\0" * len(pin)
