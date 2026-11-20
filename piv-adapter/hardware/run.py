#!/usr/bin/env python3
"""Read-only snapshots around explicitly authorized signing/decryption tests.

Run in a local Terminal: the Rust executable prompts there for an operation-
scoped PIN. This wrapper never reads, saves, logs, or forwards a PIN itself.
No reset, generation, import, management-key authentication, or policy commands
are implemented. Results contain public keys/metadata and synthetic messages.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "java", "ykman", "binary", "cert", "serial", "out", "classpath"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--preflight-only", action="store_true")
    return p.parse_args()


def snapshot(args):
    """Inspect every ordinary PIV key slot, including currently empty slots.

    Absence is recognized ONLY from the explicit 6A88 metadata status. USB,
    access, and other APDU errors stop the test rather than masquerading as an
    empty slot. Hashes identify the full public SPKI, while metadata preserves
    algorithm, origin, PIN policy and touch policy verbatim for comparison.
    """
    detected = subprocess.check_output([args.ykman, "list", "--serials"], timeout=20).decode().split()
    if args.serial not in detected:
        raise RuntimeError("Required serial is not connected; no private operation attempted")
    slots = ["9a", "9c", "9d", "9e"] + [format(n, "02x") for n in range(0x82, 0x96)]
    result = {"serial": args.serial, "slots": {}}
    for slot in slots:
        prefix = [args.ykman, "--device", args.serial, "piv", "keys"]
        read = subprocess.run(prefix + ["info", slot], capture_output=True, timeout=25)
        if read.returncode:
            if b"APDU error: SW=0x6A88" in read.stderr:
                result["slots"][slot] = {"empty": True}
                continue
            raise RuntimeError("Could not read slot " + slot + "; snapshot incomplete")
        public = subprocess.check_output(prefix + ["export", "--format", "der", slot, "-"],
                                         stderr=subprocess.PIPE, timeout=25)
        result["slots"][slot] = {"metadata": read.stdout.decode(),
                                   "sha256": hashlib.sha256(public).hexdigest()}
    return result


def logged(command, output, env=None):
    """Tee only public test status. Rust reads PINs from /dev/tty with echo off.
    There are no PIN values in command arguments, logs or environment entries.
    """
    with output.open("a") as log:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, env=env)
        try:
            # Chunk reads preserve a prompt even when it has no newline.
            while True:
                char = child.stdout.read(1)
                if not char:
                    break
                sys.stdout.write(char)
                sys.stdout.flush()
                log.write(char)
                log.flush()
            if child.wait():
                raise RuntimeError("Test command failed; no automatic retry")
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait()


def main():
    args = arguments()
    if not args.serial.isdecimal():
        raise RuntimeError("Explicit numeric serial required")
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    log = out / "test.log"
    before = None
    passed = False
    try:
        # Copy only a public certificate into this isolated result directory.
        # `inspect` rejects secret packets and verifies the subkey bindings.
        cert = out / "public.asc"
        shutil.copyfile(args.cert, cert)
        logged([args.binary, "inspect", str(cert), str(out)], log)
        before = snapshot(args)
        (out / "before.json").write_text(json.dumps(before, indent=2))
        for slot in ("9c", "84", "9d", "85"):
            expected = hashlib.sha256((out / ("expected-" + slot + ".der")).read_bytes()).hexdigest()
            if before["slots"][slot].get("sha256") != expected:
                raise RuntimeError("Certificate does not match connected key in slot " + slot)
        print("PASS public certificate matches existing slots 9c/84/9d/85", flush=True)

        java = [args.java, "-cp", args.classpath, "dev.hybridmail.PqMailInterop"]
        logged(java + ["prepare", str(cert), str(out)], log)
        if args.preflight_only:
            (out / "preflight.txt").write_text("PASS read-only preflight; no private operations performed\n")
            return

        app = Path(args.app)
        env = os.environ.copy()
        env.update(PQMAIL_PYTHON="/usr/bin/python3", PQMAIL_ADAPTERS=str(app / "adapters"),
                   OPENSSL_BIN=str(app / "native/bin/openssl"),
                   PKCS11_PROVIDER=str(app / "native/lib/pkcs11.dylib"),
                   PKCS11_MODULE=str(app / "native/lib/libykcs11.dylib"), PKCS11_SERIAL=args.serial)
        # Record the exact unchanged installed backend under test. Binary
        # hashes make it possible to distinguish adapter changes from a new
        # provider/module build when reviewing a future hardware result.
        paths = [app / "native/bin" / n for n in ("openssl", "pqmail-pkcs11-sign", "pqmail-pkcs11-kem")]
        paths += [app / "native/lib" / n for n in ("pkcs11.dylib", "libykcs11.dylib")]
        paths += [app / "adapters" / n for n in ("pkcs11-mu.py", "pkcs11-kem.py", "ykman-mu.py")]
        (out / "backend-hashes.json").write_text(json.dumps(
            {str(p.relative_to(app)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}, indent=2))
        print("Expect three PIN prompts: hybrid signing, Sequoia ciphertext decryption, PQ Mail ciphertext decryption.", flush=True)
        print("Each PIN authorizes both components of that operation, then is cleared. Touch only if the current policy requires it.", flush=True)
        logged([args.binary, "test", str(cert), str(out)], log, env)
        logged(java + ["verify", str(cert), str(out)], log)
        passed = True
    finally:
        # Compare even after a signing/decryption failure. Do not claim keys
        # are unchanged if a disconnected card prevents the after snapshot.
        if before is not None:
            after = snapshot(args)
            (out / "after.json").write_text(json.dumps(after, indent=2))
            if before != after:
                raise RuntimeError("Before/after key or policy snapshots differ; inspect before proceeding")
            (out / "unchanged.txt").write_text("PASS all 24 PIV slot states/public keys/PIN and touch policies unchanged\n")
            print("PASS all 24 PIV slot states, public keys and PIN/touch policies unchanged", flush=True)
        if passed:
            (out / "result.txt").write_text("PASS Sequoia/PIV hybrid signing, independent PQ Mail verification, Sequoia and PQ Mail ciphertext decryption, unchanged keys/policies\n")
        print("Results: " + str(out), flush=True)


if __name__ == "__main__":
    main()
