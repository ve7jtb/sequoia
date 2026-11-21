#!/usr/bin/python3
"""Public-data-only fake card for the generated Java interoperability fixture.

The serial is deliberately synthetic. Never load a physical card or accept write,
PIN, management-authentication, generation, or signature operations in this helper.
"""
import base64
import hashlib
import json
import pathlib
import struct
import sys
root=pathlib.Path(__file__).resolve().parent
assert sys.argv[1:] == ['objects','123456']
encoded=(root/'companion.pqcomp').read_bytes()
assert len(encoded)<=65536
objects={0x5f5200:b'PQCIDX01'+struct.pack('>I',len(encoded))+hashlib.sha256(encoded).digest()}
for n,start in enumerate(range(0,len(encoded),2048)):
    objects[0x5f5201+n]=b'PQCCHK01'+struct.pack('>I',n)+encoded[start:start+2048]
for line in sys.stdin:
    request=json.loads(line)
    if request['op']=='serial':value=123456
    elif request['op']=='key':
        assert request['slot'] in ['82','9c','9d','83']
        value=base64.b64encode((root/(request['slot']+'.der')).read_bytes()).decode('ascii')
    elif request['op']=='get':
        data=objects.get(request['tag'])
        value=base64.b64encode(data).decode('ascii') if data else None
    else:raise ValueError('Read-only fixture operation required')
    print(json.dumps({'value':value}),flush=True)
