"""
An implementation of attack 1 from
http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/comments/CWC-GCM/Ferguson2.pdf
"""
import Crypto.Cipher.AES as AES
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random
import sys
import requests
import socket
# wget https://raw.githubusercontent.com/niklasb/ctf-tools/master/par.py
import par
import itertools

F = GF(2)
BF.<X> = F[]
FF.<A> = GF(2 ^ 128, modulus=X ^ 128 + X ^ 7 + X ^ 2 + X + 1)

def xor(a, b):
    return ''.join(chr(ord(x)^^ord(y)) for x, y in zip(a,b))

def str2bits(str):
    res = []
    for c in str:
        res += map(int,bin(ord(c))[2:].zfill(8))
    return res

def bits2str(bits):
    bits = map(str, bits)
    res = ''
    for i in range(0, 128, 8):
        res += chr(int(''.join(bits[i:i+8]),2))
    assert len(res) == 16
    return res

def int2ele(integer):
    res = 0
    for i in range(128):
        res += (integer & 1) * (A ^ (127 - i))
        integer >>= 1
    return res

def str2ele(s):
    assert len(s) == 16
    return int2ele(bytes_to_long(s))

def ele2bits(element):
    i = element.integer_representation()
    bits = []
    while i:
        bits.append(F(i&1))
        i >>= 1
    bits += [F(0)]*(128 - len(bits))
    return bits

def bits2ele(vec):
    res = 0
    for i in range(128):
        res += vec[i]*A^i
    return res

def matrix_for_const(c):
    """ Returns the matrix representing multiplication with the element c. """
    M = [[0]*128 for i in range(128)]
    for i in range(128):
        x = A^i
        y = ele2bits(c*x)
        for j in range(128):
            M[j][i] = y[j]
    return matrix(F, M)

def square_matrix():
    """ Returns the matrix representing squaring. """
    M = [[0]*128 for i in range(128)]
    for i in range(128):
        x = A^i
        y = ele2bits(x*x)
        for j in range(128):
            M[j][i] = y[j]
    return matrix(F, M)

def get_blocks(txt):
    assert len(txt)%16 == 0
    res = []
    for i in range(0,len(txt),16):
        res.append(txt[i:i+16])
    return res

def get_coeffs(i):
    """ Compute coefficients of A^i """
    if i <= 127:
        return [i]
    x = (A^i).integer_representation()
    idx = 0
    res = []
    for idx in range(128):
        if x & 1:
            res.append(idx)
        x >>= 1
    return res

def sym_const_matrix(cvec):
    """ Return the matrix representing multiplication with the element c,
    where c is given as a vector of symbolic bits. """
    c = bits2ele(cvec)
    M = [[0]*128 for i in range(128)]
    for i in range(128):
        x = A^i
        prod = c*x
        coeffs = [F(0)]*128
        for j in range(128):
            for ci in get_coeffs(i + j):
                coeffs[ci] += cvec[j]
        for j in range(128):
            M[j][i] = coeffs[j]
    return matrix(SR, M)

def get_eqn_system_from(M, zero_rows):
    """
    Assume that the first `zero_rows` rows of M * H are zero.
    This function computes a matrix X such that H = X * P for some vector P,
    where P has `zero_rows` less dimensions than H.

    Basically X represents the linear dependencies of bits of H from each other
    that we have learned by forging a signature.
    """
    M = M[:zero_rows].echelon_form()
    pivot_cols = []
    for row in M:
        try:
            one_col = list(row).index(1)
        except ValueError:
            continue
        pivot_cols.append(one_col)
    pivots_before = 0
    res = []
    for i in range(M.ncols()):
        try:
            pivot = pivot_cols.index(i)
        except ValueError:
            pivot = None
        if pivot != None: # for pivots, use their corresponding rows with pivot columns removed
            row = list(M[pivot])
            for j in reversed(pivot_cols):
                row.pop(j)
            res.append(row)
            pivots_before += 1
        else: # for non-pivots, use a row vector with exactly a single 1 in the correct position
            row = [0]*(M.ncols() - len(pivot_cols))
            row[i - pivots_before] = 1
            res.append(row)
    return matrix(res)

def generate_kernel(blocks, Ad, bit_vars, tag_length, max_zero_rows, size=1000):
    """
    Given the bits of D_0, D_1, ... in `bit_vars`, and a symbolic representation
    of A_D in terms of these variables.

    Computes some D_i to zero out as many of the first rows of A_D zero as possible
    (but no more than the min of tag_length - 1 and max_zero_rows).

    It returns an array of arrays `diffs`, where each array represents
    the values of possible D_i as bytestrings of size 16.

    Generates `size` samples.
    """
    rows = []
    cols = Ad.ncols()
    free_variables = blocks * 128
    zero_rows = (free_variables - 1) // cols
    zero_rows_exact = float(free_variables - 1) / cols
    zero_rows = min(zero_rows, min(max_zero_rows, tag_length - 1))
    print "Unknowns: %d, free variables: %d, zero rows: %.2f / %d" % (cols, free_variables, zero_rows_exact, zero_rows)
    print "Computing kernel..."
    for i in range(zero_rows):
        for j in range(len(Ad[i])):
            zero = Ad[i,j]
            rows.append([zero.coefficient(v) for v in bit_vars])
    Z = matrix(F, rows).transpose()
    Z = Z.kernel().basis()

    res = []
    for _ in range(size):
        x = 0
        for _ in range(6):
            i = random.randrange(len(Z))
            x += Z[i]
        diffs = []
        for i in range(blocks):
            diffs.append(bits2str(x[i*128:(i+1)*128]))
        res.append(diffs)
    del Ad, Z
    return zero_rows, res

def compute_symbolic_ad(blocks):
    """
    Create a list of binary variables representing the bits of D_i and
    a representation of A_D in terms of these variables.
    """
    print "Computing symbolic A_D"
    bit_vars = [var('d_%d'% i) for i in range(0,128*max_blocks)]
    mds = [sym_const_matrix(bit_vars[i*128:(i+1)*128]) for i in range(max_blocks)]
    Ad = 0
    for i, md in enumerate(mds):
        print "  Block %d" % i
        Ad += md*M_s^(i+1)
    return Ad, bit_vars

checks_per_iteration = 100
def solve_recursively(blocks, Ad_sym, bit_vars, h_x, tag_length, max_zero_rows, oracle):
    """
    Implementation of the simple Ferguson attack on GCM.
    http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/comments/CWC-GCM/Ferguson2.pdf
    """
    print "Unknown h bits = %d" % (len(h_x[0]))
    if h_x.ncols() == 1:
        return h_x * vector([F(1)])
    while True:
        zero_rows, kernel = generate_kernel(blocks, Ad_sym, bit_vars, tag_length, max_zero_rows)
        for i in range(0, len(kernel), checks_per_iteration):
            print "Trying %d more..." % checks_per_iteration
            elements = kernel[i:i+checks_per_iteration]
            good = par.filter_parallel(oracle, elements, n=checks_per_iteration)
            if not good:
                continue
            print "Success!"
            diffs = good[0]
            print "Computing A_D * X"
            real_mds = [matrix_for_const(str2ele(diffs[i])) for i in range(blocks)]
            real_ad = sum(md*M_s^(i+1) for i, md in enumerate(real_mds)) * h_x
            for i in range(zero_rows):
                assert all(x == 0 for x in real_ad[i])
            print "Computing new X"
            new_h_x = get_eqn_system_from(real_ad, tag_length)
            if new_h_x.ncols() == 0:
                print "Done! Returning :)"
                return h_x * vector([F(1)]*h_x.ncols())
            print "Applying new X"
            h_x *= new_h_x
            Ad_sym *= new_h_x
            print "Freeing stuff"
            del real_ad, real_mds, kernel, new_h_x
            print "Recursing..."
            return solve_recursively(blocks, Ad_sym, bit_vars, h_x, tag_length, max_zero_rows, oracle)
        print "Generating new kernel vectors...."

def remote_oracle(c):
    #url = "http://gcm.ctf.bostonkey.party:32768/decrypt/"
    url = "http://127.0.0.1:8000/decrypt/"
    c = requests.post(url, data=c).content
    return "Bad auth tag" not in c

def from_char_codes(codes):
    return ''.join(map(chr, codes))

def apply_diffs(ct, diffs):
    """
    Applies the given D_i to the ciphertext `ct`
    """
    ct2 = get_blocks(ct)
    for i, diff in enumerate(diffs):
        pos = 1 - 2**(i+1)
        assert pos < 0 and -pos <= len(ct2)
        ct2[pos] = xor(ct2[pos], diff)
    ct2 = ''.join(ct2)
    return ct2

if __name__ == "__main__":
    remote_iv = from_char_codes([102, 97, 110, 116, 97, 115, 116, 105, 99, 32, 105, 118])
    remote_ct = open('ciphertext').read()
    remote_tag = from_char_codes([178, 191])
    #remote_ct = open('ciphertext_remote').read()
    #remote_tag = from_char_codes([119, 179])
    assert remote_oracle(remote_iv + remote_ct + remote_tag)

    def oracle(diffs):
        ct2 = apply_diffs(remote_ct, diffs)
        ct_ = remote_iv + ct2 + remote_tag
        remote = remote_oracle(remote_iv + ct2 + remote_tag)
        return remote

    tag_length = 16
    # we will learn (tag_length - max_zero_rows) bits of H per iteration. But we
    # will also need (tag_length - max_zero_rows) queries per iteration.
    max_zero_rows = 7
    # the more blocks we use, the more expensive (CPU and memory-wise) the computations
    # but the more bits we will learn (and less queries we need) in the first few
    # iterations of the attack
    max_blocks = 4

    M_s = square_matrix()
    Ad, bit_vars = compute_symbolic_ad(max_blocks)
    ID = matrix(F, 128, 128, 1)
    hbits = solve_recursively(max_blocks, Ad, bit_vars, ID, tag_length, max_zero_rows, oracle)
    print "====================================="
    print "BKPCTF{%016x}" % bytes_to_long(bits2str(hbits))
