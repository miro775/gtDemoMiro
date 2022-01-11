
# https://pycose.readthedocs.io/en/latest/examples.html

from binascii import unhexlify, hexlify

from cose.messages import Sign1Message, CoseMessage
from cose.keys import CoseKey
from cose.headers import Algorithm, KID
from cose.algorithms import EdDSA
from cose.keys.curves import Ed25519
from cose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from cose.keys.keytype import KtyOKP
from cose.keys.keyops import SignOp, VerifyOp

msg = Sign1Message(
    phdr = {Algorithm: EdDSA, KID: b'kid2'},
    payload = 'signed message'.encode('utf-8'))

print(msg)  #  <COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'' ... (0 B)]>

cose_key = {
    KpKty: KtyOKP,
    OKPKpCurve: Ed25519,
    KpKeyOps: [SignOp, VerifyOp],
    OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
    OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')}

cose_key = CoseKey.from_dict(cose_key)

print(cose_key) # <COSE_Key(OKPKey): {'OKPKpD': "b'\\x9da\\xb1\\x9d\\xef' ... (32 B)", 'OKPKpX': "b'\\xd7Z\\x98\\x01\\x82' ... (32 B)", 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP', 'KpKeyOps': ['SignOp', 'VerifyOp']}>

msg.key = cose_key
# the encode() function performs the signing automatically
encoded = msg.encode()
print(encoded) # b'\xd2\x84I\xa2\x01\'\x04Dkid2\xa0Nsigned messageX@\xcc\x87f_\xfd?\xa3=\x96\xf3\xb6\x06\xfc\xed\xea\xef\x83\x94#"\x18r\xd0\xbf\xa1\x96\xe0i\xa1\x89\xa6\x07\xc2(I$\xc3\xab\xb8\x0e\x94$f\xcd0\x0c\xc5\xd1\x8f\xe4\xe5\xea\x1f>\xbd\xb6.\xf8A\x91\tD}\x03'
hexlify(encoded)


# decode and verify the signature
decoded = CoseMessage.decode(encoded)
print(decoded)  # <COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'\xcc\x87f_\xfd' ... (64 B)]>


decoded.key = cose_key
print(decoded.verify_signature())  # True

print(decoded.payload)  # b'signed message'