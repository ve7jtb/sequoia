#!/usr/bin/env python3
"""PIN-free bundle restore with complete before/after key and policy snapshots.

No mail, provisioning, management-key authentication or private operations.
The output contains public device identifiers/certificates; keep it private.
"""
import argparse
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from run import snapshot

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('helper','binary','ykman','serial','out'):
        p.add_argument('--'+name,required=True)
    a=p.parse_args()
    out=Path(a.out)
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    before=snapshot(a)
    (out/'before.json').write_text(json.dumps(before,indent=2))
    try:
        result=subprocess.run([a.binary,a.helper,a.serial,str(out/'restored')],capture_output=True,text=True,timeout=180)
        (out/'restore.log').write_text(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError('Restore failed; see restore.log; no private operation was attempted')
        # Feed the restored certificate to the unchanged adapter's selector.
        inspect=Path(a.binary).with_name('piv-test')
        result=subprocess.run([str(inspect),'inspect',str(out/'restored/openpgp-v6.asc'),str(out)],capture_output=True,text=True,timeout=30)
        (out/'inspect.log').write_text(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError('Restored certificate not accepted by existing adapter')
        print('PASS bundle restored; existing adapter accepts hybrid signing/decryption keys')
    finally:
        after=snapshot(a)
        (out/'after.json').write_text(json.dumps(after,indent=2))
        if before!=after:
            raise RuntimeError('Slot snapshot changed; inspect results')
        (out/'unchanged.txt').write_text('PASS all 24 ordinary slot states, public keys, origins, PIN and touch policies unchanged\n')
        print('PASS all 24 slot/key/policy snapshots unchanged')
    (out/'result.txt').write_text('PASS PIN-free restore, Sequoia selection, no trust grant, unchanged keys and policies\n')
    print('Results: '+str(out))
if __name__=='__main__':main()
