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
