import zlib, base45, cbor, pprint
import cbor2
import json

from cose.headers import Algorithm, KID
from cose.messages import CoseMessage
from cose.keys import cosekey, ec2, keyops, keyparam, curves, keytype
from cose import algorithms

"""
https://www.zive.cz/clanky/v-evropskem-ockovacim-qr-kodu-ktery-budete-ukazovat-na-dovolene-se-skryva-zakodovany-text-takhle-ho-prectete/sc-3-a-210469/default.aspx


# https://blog.hqcodeshop.fi/archives/516-Decoding-EU-Digital-COVID-Certificate.html
# code from  https://github.com/HQJaTu/vacdec/tree/certificate-fetch

# https://frank.sauerburger.io/2021/06/16/decode-vaccination-certification.html

https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
tag 18=	COSE_Sign1	COSE Single Signer Data Object	https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-struct/15/

# cosemessage  https://pycose.readthedocs.io/en/latest/
# https://pycose.readthedocs.io/en/latest/cose/messages/sign1message.html


# druha davka 1.7.2021
HC1:NCFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769Y3S3XHW3Q6R5*F9L7U4FC3K9EXNFAPQHIZC4.OI1RM8ZA*LPVT2L+9G4LF4UGEG%80C0I$6UU6TY2I IG8LOG:D39UT4LS6S:%4YE9/MVEK0*LA/CJ6IAXPMHQ1*P1MX1+ZEOQ1OH6ZK5PVFNXUJRH0LH%Y2 UQ7S7TK24H9-78VNI:RA-CT5-QAQ1.EKAOGK KR+P*$K3$OHBW24FAL86H0YQCIA2IE9WT0K3M9UVZSVV*001HW%8UE9.955B9-NT0 2$$0X4PCY0+-CVYCDEBD0HX2JR$4O1K8KES/F-1JZ.KBIH6JK 3MGEC.-B97U: K/YN8AMNHSI%KZYN25CW74$6C0BP3-S-YNHDMBLE/*BLJ8FT5D75W9AV88H76TE8+FFSXDMGR8*LRM5S+QF4QV.8-RV$4782F5$8YCSD2RA+O* 9B7RAOGF7GV8U*Z0B:VL8S+$C/LRHSC0LV0%G3AODO1.-760K9/S%00SE1D1

HC1:NCFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769Y3S3XHW3Q6R5*F9L7U4FC3K9EXNFAPQHIZC4.OI1RM8ZA*LPVT2L+9G4LF4UGEG%80C0I$6UU6TY2I IG8LOG:D39UT4LS6S:%4YE9/MVEK0*LA/CJ6IAXPMHQ1*P1MX1+ZEOQ1OH6ZK5PVFNXUJRH0LH%Y2 UQ7S7TK24H9-78VNI:RA-CT5-QAQ1.EKAOGK KR+P*$K3$OHBW24FAL86H0YQCIA2IE9WT0K3M9UVZSVV*001HW%8UE9.955B9-NT0 2$$0X4PCY0+-CVYCDEBD0HX2JR$4O1K8KES/F-1JZ.KBIH6JK 3MGEC.-B97U: K/YN8AMNHSI%KZYN25CW74$6C0BP3-S-YNHDMBLE/*BLJ8FT5D75W9AV88H76TE8+FFSXDMGR8*LRM5S+QF4QV.8-RV$4782F5$8YCSD2RA+O* 9B7RAOGF7GV8U*Z0B:VL8S+$C/LRHSC0LV0%G3AODO1.-760K9/S%00SE1D1

# ocko,uzis, download 1.9.2021,  certi. identifikator:  URN:UVCI:01:CZ:YJUECJ77ZGMQ38DT4D2KU9KSBT7DBZQZ
HC1:NCFTZ8VX7OD0%20XKNZSRIC6U48MOKF$UKFV-%TCFH.CQ$VKVR7FNPX6UGEUKP6:R2I O JKDD4EDJ 1N.IE1X9HB8PPDFS8CB8-P6P*H--MJX50DQ*R1N3W+5AR+8K9VP3P.JS0UEB-TCCH$H7QR0A8UFM0D.NL4H-*D:BF1+A%RTD%CZHGJ/BER4.JQKX4W9I:78Z44FOA3ED3314XJ2DHW43V28IWVIGFW7KEXVJ$JD15$VCMM18/3+-P:YK%97MGQHN0-618TQU0R6BHKST VLJ4TL KMB8MKPRLRQQM.MJIAB-BERA5R.OX I*96PO23E5Z49620HNN0:6RPHEC70KG%T1NITYZ7/%L0341UKRAB..C%00LEASCJI626S1$V6-RL*YIYU7ZNIX 4IAHK:ODVKIJLF-KSD0.$PRP4C/8PL1YD92-6R9O$N6+0VSL59D94-5ZV0B6D4/9*B58DWJD0NDU/4F.2QAM7G/0R1BHUG5-2GIE5RQ94NBSGVHDZ9BDU3C/L/RTV2E.%D0MORSV43KOAP+SJYYRE09LK27EG




cbor2.loads( decompressed )=
CBORTag(18, [b'\xa1\x01&', {4: b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01...............................


https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-struct/15/   CBOR Tag=18 = COSE_Sign1

cose_msg=
<COSE_Sign1: [{'Algorithm': 'Es256'}, {'KID': b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01bCZ' ... (269 B), b'+C\x93]o' ... (64 B)]>


The text of the QR code contains a human-readable version identifier, usually, HC1 followed by a colon. To proceed, we chop off this part.
The actual binary data is base45 encoded and needs to be decoded.
The COSE message itself is ZLib compressed and needs to be decompressed before we can,
Finally, parse the COSE message and its payload.

"""

print("Zkopíruj obsah QR kódu: HC1:..... ", end="")
in_str = input()[4:]
# pprint.pprint(cbor.loads(cbor.loads(zlib.decompress(base45.b45decode(input()[4:]))).value[2]))
pprint.pprint(cbor.loads(cbor.loads(zlib.decompress(base45.b45decode( in_str ))).value[2]))

'''
{-260: {1: {'dob': '1974-12-31',
            'nam': {'fn': 'JUST',
                    'fnt': 'JUST',
                    'gn': 'MIROSLAV',
                    'gnt': 'MIROSLAV'},
            'v': [{'ci': 'BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54N',
                   'co': 'CZ',
                   'dn': 2,
                   'dt': '2021-07-01',
                   'is': 'Ministry of Health of the Czech Republic',
                   'ma': 'ORG-100030215',
                   'mp': 'EU/1/20/1528',
                   'sd': 2,
                   'tg': '840539006',
                   'vp': '1119349007'}],
            'ver': '1.0.1'}},
 1: 'CZ',
 4: 1656675788,
 6: 1625139788}
 
 
---# nove verze:

{-260: {1: {'dob': '1974-12-31',
            'nam': {'fn': 'JUST',
                    'fnt': 'JUST',
                    'gn': 'MIROSLAV',
                    'gnt': 'MIROSLAV'},
            'v': [{'ci': 'URN:UVCI:01:CZ:YJUECJ77ZGMQ38DT4D2KU9KSBT7DBZQZ',
                   'co': 'CZ',
                   'dn': 2,
                   'dt': '2021-07-01',
                   'is': 'Ministry of Health of the Czech Republic',
                   'ma': 'ORG-100030215',
                   'mp': 'EU/1/20/1528',
                   'sd': 2,
                   'tg': '840539006',
                   'vp': '1119349007'}],
            'ver': '1.3.0'}},
 1: 'CZ',
 4: 1662038147,
 6: 1630502147}

 
'''


# Code adapted from:
# https://alphalist.com/blog/the-use-of-blockchain-for-verification-eu-vaccines-passport-program-and-more

# Strip the first characters to form valid Base45-encoded data
b45data =  in_str #cert[4:]

# Decode the data
zlibdata = base45.b45decode(b45data)
print("b45decode=")
print(zlibdata)
# b'x\xda\xbb\xd4\xe2\xbc\x90Qm!\x8bGu\xa7\xfb\x8b>%\x83\xe6HF\xde%\x8cI\xceQ,RI\xfb\xee\x9ea\x93J\xb8\xbb\xca\xc7\x92\x91y!\xe3\x92\xc4\xb2\xc6UI\xc9\x99\x15\nNN\xa6\xe1\xee\x11\x81\x16\x01\x8e\x8en\xee\x81\xe6\x91\x8e\xde\x81\xde\xc1\x91n\xa1\xee\xe6\xa6\xee\xde\xa6&~I\xc9\xf9@\x03\x92R\xf2\x98\x92RJ\xb2\x8c\x0c\x8c\x0cu\r\xccu\r\x0c\x932\x8b+4|3\xf32\x8bK\x8a*\x15\xf2\xd3\x14<R\x13sJ2@\xac\x92\x8cT\x05\xe7\xaa\xd4\xe4\x0c\x85\xa0\xd4\x82\xd2\xa4\x9c\xcc\xe4\xa4\xdc\xc4\\\xff w]C\x03\x03\x03c\xa0\x11\xa6I\xb9\x059\xae\xa1\xfa\x86\xfaF\x06\xfa\x86\xa6F\x16I\xc5)LI%\xe9\x99\x16&\x06\xa6\xc6\x96\x06\x06fIe\x05Y\x86\x86\x86\x96\xc6&@\x9eyrJ~R\x96\xa1\xa5\xb9\x89\xae\xa1\x91\xae\xb1ar^b\xee\x92\xa4\xb4\xbc\x14\xaf\xd0\xe0\x90\xa4\xf4\xbc\x0c_\xcf \xff`\x1f\xc7\xb0\xe4\xb4\xbc\x12\xb0`rz^\tB\xb4,\xb5(\xd5P\xcf@\xcf0\xc2A\xdbyrl\xbe\xd8y\xad\x00+\x86\xd4\xce\xcemF\xc9\xfa\x1f88w\tE\xce\xdf\xba\xd5\xfa\xc4\xeaM\xac\xd6\xd9\x82\xd2\x7f\xda\xee\xd5\x06N\xfc\xfe\xde\xf9e\x95\xd9oc\xe9\xf8\xe8\x85>\xbf\x9d\x0c.>\xbe\x9e:\xe5\x14\x00&\n{:'

# Uncompress the data
decompressed = zlib.decompress(zlibdata)
print("zlib.decompress=")
print(decompressed)
# b'\xd2\x84C\xa1\x01&\xa1\x04H{\x89G\xe8\x8e"0\x83Y\x01\r\xa4\x01bCZ\x04\x1ab\xbe\xdd\xcc\x06\x1a`\xdd\xaaL9\x01\x03\xa1\x01\xa4av\x81\xaabcix BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54NbcobCZbdn\x02bdtj2021-07-01bisx(Ministry of Health of the Czech RepublicbmamORG-100030215bmplEU/1/20/1528bsd\x02btgi840539006bvpj1119349007cdobj1974-12-31cnam\xa4bfndJUSTbgnhMIROSLAVcfntdJUSTcgnthMIROSLAVcvere1.0.1X@+C\x93]o\x16\xcf*P:\x00e\x89\x89\xb62c/\xf0\x08\t\xba\x12Y\x9f\xb5\xb5;\xc8\xab\xb2\x05;k\x11\x1b\xfc\x86\xde}Q\x91\xf7\xefC\xe9z6\xfb3\x1b_[\xa1L\xfbB0\xd1\xe3\xd7e\x94\xca'



print("cbor2.loads( decompressed )=")
print( cbor2.loads( decompressed ) )
# CBORTag(18, [b'\xa1\x01&', {4: b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01b.......................

cbor_raw = cbor2.loads( decompressed )
print("cbor_raw=")
print(cbor_raw)

#print(cbor2.loads(cbor2.loads(decompressed).value[0]))  # {1: -7}
#print(cbor2.loads(cbor2.loads(decompressed).value[1]))
#print(cbor2.loads(cbor2.loads(decompressed).value[2]))  # {1: 'CZ', 4: 1656675788, 6: 1625139788, -260: {1:.........
#print(cbor2.loads(cbor2.loads(decompressed).value[3]))  # -12



# decode COSE message (no signature verification done)
cose_msg = CoseMessage.decode(decompressed)
print("cose_msg=")
print(cose_msg)
# <COSE_Sign1: [{'Algorithm': 'Es256'}, {'KID': b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01bCZ' ... (269 B), b'+C\x93]o' ... (64 B)]>


# decode the CBOR encoded payload and print as json
print("cose_msg.phdr=")
pprint.pprint(cose_msg.phdr)
# {<class 'cose.headers.Algorithm'>: <class 'cose.algorithms.Es256'>}

print("cose_msg.uhdr=")
pprint.pprint(cose_msg.uhdr)
# {<class 'cose.headers.KID'>: b'{\x89G\xe8\x8e"0\x83'}

# print("cose_msg.uhdr[KID].hex: {0}".format(cose_msg.uhdr[KID].hex()))  # cose_msg.uhdr[KID].hex: 7b8947e88e223083

pkid, ukid = cose_msg.phdr.get(KID), cose_msg.uhdr.get(KID)
if not pkid and not ukid:
    print("Certificate is not signed")
else:
    if (pkid and ukid) and (pkid != ukid):
        print("Both protected and unprotected headers contain differing key references, defaulting to the protected one")
    elif ukid and not pkid:
        print("Protected header key reference missing, using the unprotected one")
    kid = pkid or ukid
    print("COVID certificate signed with X.509 certificate.")
    print("X.509 in DER form has SHA-256 beginning with: {0}".format(kid.hex()))  #  7b8947e88e223083

print("cose_msg.key=")
pprint.pprint(cose_msg.key)

print("cose_msg.signature=")
pprint.pprint(cose_msg.signature)
cbos_sign = cbor2.loads(cose_msg.signature)
pprint.pprint(cbos_sign)  # -12
'''
(b'+C\x93]o\x16\xcf*P:\x00e\x89\x89\xb62c/\xf0\x08\t\xba\x12Y\x9f\xb5\xb5;'
 b'\xc8\xab\xb2\x05;k\x11\x1b\xfc\x86\xde}Q\x91\xf7\xefC\xe9z6\xfb3\x1b_'
 b'[\xa1L\xfbB0\xd1\xe3\xd7e\x94\xca')
'''
#sig = CoseMessage.decode(cose_msg.signature)
#print(sig)

print("--------")


#------------------- cose_msg.payload, json data: ---------------------------------------------------------
cbor = cbor2.loads(cose_msg.payload)
print("cose_msg.payload=")
print(cbor)
# {1: 'CZ', 4: 1656675788, 6: 1625139788, -260: {1: {'v': [{'ci': 'BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54N', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-01', 'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2, 'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-12-31', 'nam': {'fn': 'JUST', 'gn': 'MIROSLAV', 'fnt': 'JUST', 'gnt': 'MIROSLAV'}, 'ver': '1.0.1'}}}
# {1: 'CZ', 4: 1662038147, 6: 1630502147, -260: {1: {'v': [{'ci': 'URN:UVCI:01:CZ:YJUECJ77ZGMQ38DT4D2KU9KSBT7DBZQZ', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-01', 'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2, 'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-12-31', 'nam': {'fn': 'JUST', 'gn': 'MIROSLAV', 'fnt': 'JUST', 'gnt': 'MIROSLAV'}, 'ver': '1.3.0'}}}



# Note: Some countries have hour:minute:secod for sc-field (Date/Time of Sample Collection).
# If used, this will decode as a datetime. A datetime cannot be JSON-serialized without hints (use str as default).
# Note 2: Names may contain non-ASCII characters in UTF-8
pprint.pprint("Certificate as JSON: {0}".format(json.dumps(cbor, indent=2, default=str, ensure_ascii=False)))

#----------------------------------------------------------------------


#cose2encode = cose_msg.encode(tag=True, sign=True) # cose.exceptions.CoseException: Key cannot be None
cose2encode = cose_msg.encode(tag=True, sign=False)

print("cose_msg.encode=")
print(cose2encode)
#b'\xd2\x83C\xa1\x01&\xa1\x04H{\x89G\xe8\x8e"0\x83Y\x01\r\xa4\x01bCZ\x04\x1ab\xbe\xdd\xcc\x06\x1a`\xdd\xaaL9\x01\x03\xa1\x01\xa4av\x81\xaabcix BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54NbcobCZbdn\x02bdtj2021-07-01bisx(Ministry of Health of the Czech RepublicbmamORG-100030215bmplEU/1/20/1528bsd\x02btgi840539006bvpj1119349007cdobj1974-12-31cnam\xa4bfndJUSTbgnhMIROSLAVcfntdJUSTcgnthMIROSLAVcvere1.0.1'
#origin:
#b'\xd2\x84C\xa1\x01&\xa1\x04H{\x89G\xe8\x8e"0\x83Y\x01\r\xa4\x01bCZ\x04\x1ab\xbe\xdd\xcc\x06\x1a`\xdd\xaaL9\x01\x03\xa1\x01\xa4av\x81\xaabcix BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54NbcobCZbdn\x02bdtj2021-07-01bisx(Ministry of Health of the Czech RepublicbmamORG-100030215bmplEU/1/20/1528bsd\x02btgi840539006bvpj1119349007cdobj1974-12-31cnam\xa4bfndJUSTbgnhMIROSLAVcfntdJUSTcgnthMIROSLAVcvere1.0.1X@+C\x93]o\x16\xcf*P:\x00e\x89\x89\xb62c/\xf0\x08\t\xba\x12Y\x9f\xb5\xb5;\xc8\xab\xb2\x05;k\x11\x1b\xfc\x86\xde}Q\x91\xf7\xefC\xe9z6\xfb3\x1b_[\xa1L\xfbB0\xd1\xe3\xd7e\x94\xca'



cosemsg_as_cbor = cbor2.dumps(cose2encode)
print("cosemsg_as_cbor=")
print(cosemsg_as_cbor)
# b'Y\x01!\xd2\x83C\xa1\x01&\xa1\x04H{\x89G\xe8\x8e"0\x83Y\x01\r\xa4\x01bCZ\x04\x1ab\xbe\xdd\xcc\x06\x1a`\xdd\xaaL9\x01\x03\xa1\x01\xa4av\x81\xaabcix BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54NbcobCZbdn\x02bdtj2021-07-01bisx(Ministry of Health of the Czech RepublicbmamORG-100030215bmplEU/1/20/1528bsd\x02btgi840539006bvpj1119349007cdobj1974-12-31cnam\xa4bfndJUSTbgnhMIROSLAVcfntdJUSTcgnthMIROSLAVcvere1.0.1'

kompres1 = zlib.compress( cosemsg_as_cbor )
print('compress, cosemsg_as_cbor=')
print(kompres1)

b45str = base45.b45encode(kompres1)
print('b45str=')
print(b45str)
# b'6BFTZ8.-NJPO/23:MA00E%10U EG+5HFV.5IP8P*XKW641LB9:9$TNT$MS.N6IT/BKZ1HG/O944JQSLUFN:4:-EXN87EEI9TA.4+%1R3J6+ID%N44FI6S6FU3N49Q1CTGKDGSZVLI0-3N2 VC8H$1L.81ZL5PY3U1CD99J-G9NDTANV1SL%NJ1UBL6OF0437 EFX9P8S1VPT0QR%QQ727JDH4866PAC35982CG4GGD647/XKV:L9*TWT5XICZZ1K4K7E2KLC-:V*VQ/YE4RURVM8IC.4TFBRO8G+QKK 2V5TI1FPUP6L59 0VC6JMHTDP8KLZ82**MTD7SEFKS0IQ9P/E1HQ8DOR8B2*48H4368RDJHHE%LKZCSR1P L9JETNIQ4WRKYE/HVIXK37PAXTA3K4EQP%9+60.WR61'



'''
cosemsg_as_cbor = cbor2.dumps(cose_msg)
# error:  _cbor2.CBOREncodeTypeError: cannot serialize type <class 'cose.messages.sign1message.Sign1Message'>

print("cosemsg_as_cbor=")
pprint.pprint(cosemsg_as_cbor)

kompres1 = zlib.compress( cosemsg_as_cbor )
print('compress, cosemsg_as_cbor=')
print(kompres1)

b45str1 = base45.b45encode(kompres1)
print('base45,cosemsg_as_cbor=')
print(b45str1)
'''