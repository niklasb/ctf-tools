def format_asn_genconf(N, e, p, q):
    d = inverse_mod(e, (p-1)*(q-1))
    e1 = d % (p-1)
    e2 = d % (q-1)
    coeff = inverse_mod(q, p)
    return """
asn1=SEQUENCE:rsa_key

[rsa_key]
version=INTEGER:0
modulus=INTEGER:{N}
pubExp=INTEGER:{e}
privExp=INTEGER:{d}
p=INTEGER:{p}
q=INTEGER:{q}
e1=INTEGER:{e1}
e2=INTEGER:{e2}
coeff=INTEGER:{coeff}
""".strip().format(**locals()) + "\n"

# assemble ASN RSA key, pack as PEM
def write_privkey_pem(N, e, p, q, outfile='privkey.pem'):
    asn = format_asn_genconf(N, e, p, q)
    with tempfile.NamedTemporaryFile() as tmp1:
        with tempfile.NamedTemporaryFile() as tmp2:
            tmp1.write(asn)
            tmp1.flush()
            os.system('openssl asn1parse -genconf %s -out %s' % (tmp1.name, tmp2.name))
            os.system('openssl rsa -in %s -inform der -out %s' % (tmp2.name, outfile))

def openssl_smime_decrypt(enc_file, key='privkey.pem', keyform='pem'):
    os.system('openssl smime -decrypt -inkey %s -inform %s -in %s' % (key, keyform, enc_file))

"""
Random OpenSSL notes:
------------------------------

Show data in PCKS#7 / S/MIME format:

    $ openssl cms -in flag.enc -inform pem -noout -cmsout -print
    CMS_ContentInfo:
    contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
    d.envelopedData:
        version: <ABSENT>
        originatorInfo: <ABSENT>
        recipientInfos:
        d.ktri:
            version: <ABSENT>
            d.issuerAndSerialNumber:
            issuer: C=NL, ST=Noord-Holland, L=Amsterdam, O=HITB, OU=CTF
            serialNumber: 9961588921524517526
            keyEncryptionAlgorithm:
            algorithm: rsaEncryption (1.2.840.113549.1.1.1)
            parameter: NULL
            encryptedKey:
            0000 - 65 e4 4e 45 2e 29 36 90-5c b7 93 b7 ad da db   e.NE.)6.\......
            000f - b2 2f 40 e9 0b c1 df bd-2c 1d fa 65 2a f1 78   ./@.....,..e*.x
            001e - 6b 08 40 d8 5a c7 7a 44-d1 a6 fa cb d0 bb da   k.@.Z.zD.......
            002d - 12 d1 0a f7 33 c7 4b 4e-3e cb 14 64 f3 78 0b   ....3.KN>..d.x.
            003c - 89 26 5f 24 4c 1d 67 6e-72 ad 35 e6 98 4c 2c   .&_$L.gnr.5..L,
            004b - b1 b9 ad 0d 3f bf e3 10-7c 35 38 7f 63 8b 82   ....?...|58.c..
            005a - 77 98 ad b4 07 a9 71 95-4f ef 49 a7 93 93 78   w.....q.O.I...x
            0069 - 4f 0e fb 10 8c d8 95 74-fa 0b 75 3c df 4e 31   O......t..u<.N1
            0078 - cc ef 97 67 01 03 3f 2a-                       ...g..?*
        encryptedContentInfo:
        contentType: pkcs7-data (1.2.840.113549.1.7.1)
        contentEncryptionAlgorithm:
            algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
            parameter: OCTET STRING:
            0000 - 66 81 bb 1b 23 2d 09 2d-20 53 1c af fb c1 12   f...#-.- S.....
            000f - 05                                             .
        encryptedContent:
            0000 - f7 75 9e 84 28 bf ad 4e-3a 2f 32 1e 1e 25 9f   .u..(..N:/2..%.
            000f - 8b 09 e3 be af 1c 41 b5-17 f9 96 ae 62 29 d2   ......A.....b).
            001e - 52 f5 ee 4f a7 8e 51 3e-fd 34 0c 7f 74 21 49   R..O..Q>.4..t!I
            002d - a9 45 07 64 e7 fc cc 4f-be 11 8b c4 7d 4e fc   .E.d...O....}N.
            003c - 17 79 71 5a a0 ef bb 34-c3 e8 bb bc f7 e1 9a   .yqZ...4.......
            004b - 9f cb 4e e5 a9 24 f2 8d-33 41 04 a2 73 98 53   ..N..$..3A..s.S
            005a - 99 38 c8 03 ab 2e 6c 5e-61 9a fb de 7b 61 5f   .8....l^a...{a_
            0069 - e9 70 19 24 5c ff bf                           .p.$\..
        unprotectedAttrs:
        <EMPTY>

Parse ASN1: Crypt.Util.asn1
