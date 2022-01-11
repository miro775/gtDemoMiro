"""
# download CBOR [ pypi.org/project/cbor/ ] and instal:


# only 1davka: 20.5.==================================
HC1:NCFTZ8B8O8D0PS3VKN54NL84SZJ*MHK78%DUUUNH+18N6WP5YBA%ML$*N6UN8EUATF7/RX+AR59*D8%+QNNEC+S-OA:$D6+MQ:V:0RTDQ:CB0 R/WUY%7L.2:7K%/U5LLDZPC8I3P2YDS4/84P3H+13D4X/JUGIXKST$5L+RSBQK:QHSMI%Q1HU+M40EDGMDIGI10Q$ 86 AI:CVE4TKHBQK0AEH*AVL0V131NJKG476CNIP-B8QKNOPVV-OUARG3IGOHS7L.:MTJJL+SMI7:U7+KLPETEIDTOPLU0$+M2KNL60DZGJJOD%04JB3VRKWS.B8QS5S53OPR99FLK5W94ASAMLH9.N8OOAN5XT6D75WF5DPOCSAK36OS8YHJGAN:AC85TI.FROH$T98%SHPV2 O+Y6UAVPFD1JFP/M.L7A-BFO9P6EO-C4NMC Q5SCI5TKYL-6F:TSX.M54SLGBO6D7CSUTQYRD18K0DBCYHGZ7FO6BYN8YE2DN5SFZOBS*F$ K-9L2DVZQUQ:6:JF

result=
{1: 'CZ', 4: 1654747829, 6: 1623211829, -260: {1: {'v': [{'ci': 'nd2ahm4axr43dtu7bs9enhs32k7f3fxr', 'co': 'CZ', 'dn': 1, 'dt': '2021-05-20', 'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2, 'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-12-31', 'nam': {'fn': 'JUST', 'gn': 'MIROSLAV', 'fnt': 'JUST', 'gnt': 'MIROSLAV'}, 'ver': '1.0.1'}}}

https://www.unixtimestamp.com/
1654747829 = Thu Jun 09 2022 04:10:29 GMT+0000
1623211829 = Wed Jun 09 2021 04:10:29 GMT+0000

# druha davka 1.7.2021
HC1:NCFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769Y3S3XHW3Q6R5*F9L7U4FC3K9EXNFAPQHIZC4.OI1RM8ZA*LPVT2L+9G4LF4UGEG%80C0I$6UU6TY2I IG8LOG:D39UT4LS6S:%4YE9/MVEK0*LA/CJ6IAXPMHQ1*P1MX1+ZEOQ1OH6ZK5PVFNXUJRH0LH%Y2 UQ7S7TK24H9-78VNI:RA-CT5-QAQ1.EKAOGK KR+P*$K3$OHBW24FAL86H0YQCIA2IE9WT0K3M9UVZSVV*001HW%8UE9.955B9-NT0 2$$0X4PCY0+-CVYCDEBD0HX2JR$4O1K8KES/F-1JZ.KBIH6JK 3MGEC.-B97U: K/YN8AMNHSI%KZYN25CW74$6C0BP3-S-YNHDMBLE/*BLJ8FT5D75W9AV88H76TE8+FFSXDMGR8*LRM5S+QF4QV.8-RV$4782F5$8YCSD2RA+O* 9B7RAOGF7GV8U*Z0B:VL8S+$C/LRHSC0LV0%G3AODO1.-760K9/S%00SE1D1

result=
---cbor----
{1: 'CZ', 4: 1656675788, 6: 1625139788, -260: {1: {'v': [{'ci': 'BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54N', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-01', 'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2, 'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-12-31', 'nam': {'fn': 'JUST', 'gn': 'MIROSLAV', 'fnt': 'JUST', 'gnt': 'MIROSLAV'}, 'ver': '1.0.1'}}}

1656675788 = Fri Jul 01 2022 11:43:08 GMT+0000
1625139788 = Thu Jul 01 2021 11:43:08 GMT+0000  ,  Your Time Zone	Thu Jul 01 2021 13:43:08 GMT+0200 (Central European Summer Time)



https://blog.hqcodeshop.fi/archives/516-Decoding-EU-Digital-COVID-Certificate.html


"""

import zlib, base45, cbor, pprint
import cbor2

print("Zkopíruj obsah QR kódu: ", end="")
in_str = input()[4:]
# pprint.pprint(cbor.loads(cbor.loads(zlib.decompress(base45.b45decode(input()[4:]))).value[2]))
pprint.pprint(cbor.loads(cbor.loads(zlib.decompress(base45.b45decode( in_str ))).value[2]))


print("----base45----------")
b45_str = base45.b45decode( in_str )
print(b45_str)


b45str_encode = base45.b45encode(b45_str)
print('b45str_encode ,   ENCODE  again=')
print(b45str_encode)

print("----base45--zlib.decompress--------")
decomp_str = zlib.decompress( b45_str )
print(decomp_str)

print("----base45--zlib.decompress----cbor.loads.value[2]----")
cbor_obj_v2 = cbor.loads(  decomp_str ).value[2]
print(cbor_obj_v2)


print("---cbor--from v2--")
cbor_obj2b = cbor.loads(cbor_obj_v2)
print(cbor_obj2b)

print("---cbor2--####")   #  CBORTag(18, [b'\xa1\x01&', {4: b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01
cob2 = cbor2.loads(cbor2.loads(decomp_str).value[0])
pprint.pprint(cob2)  #  {1: -7}   ?COSE


print("----base45--zlib.decompress----cbor.loads   full ? -vX---")
cbor_obj_vX = cbor.loads(  decomp_str )
print(cbor_obj_vX)
# Tag(18, [b'\xa1\x01&', {4: b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01bCZ\x04\x1ab\xbe\xdd\xcc\x06\x1a`\xdd\xaaL9\x01\x03\xa1\x01\xa4av\x81\xaabcix BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54NbcobCZbdn\x02bdtj2021-07-01bisx(Ministry of Health of the Czech RepublicbmamORG-100030215bmplEU/1/20/1528bsd\x02btgi840539006bvpj1119349007cdobj1974-12-31cnam\xa4bfndJUSTbgnhMIROSLAVcfntdJUSTcgnthMIROSLAVcvere1.0.1', b'+C\x93]o\x16\xcf*P:\x00e\x89\x89\xb62c/\xf0\x08\t\xba\x12Y\x9f\xb5\xb5;\xc8\xab\xb2\x05;k\x11\x1b\xfc\x86\xde}Q\x91\xf7\xefC\xe9z6\xfb3\x1b_[\xa1L\xfbB0\xd1\xe3\xd7e\x94\xca'])
# TypeError: a bytes-like object is required, not 'Tag'  ---->>>  cbor_X = cbor.loads(cbor_obj_vX)





#print("----base45--zlib.decompress----cbor.loads.value[1]--???--")
#cbor_obj_v1 = cbor.loads(  decomp_str ).value[1]
#print(cbor_obj_v1)

#print("----base45--zlib.decompress----cbor.loads.value[0]--???--")
#cbor_obj_v0 = cbor.loads(  decomp_str ).value[0]
#print(cbor_obj_v0)


#print("---cbor--from v0--")
#cbor_obj0b = cbor.loads(cbor_obj_v0)
#print(cbor_obj0b)



