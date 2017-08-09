#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# adapted from https://raw.githubusercontent.com/ipfans/pyAES
#
# LICENSE: https://github.com/ipfans/pyAES/blob/master/LICENSE
#
# The MIT License (MIT)
#
# Copyright (c) 2014 ipfans
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import array

def ary(x):
    return array.array('B', x)

def to_hex(x):
    return ' '.join('%02x' % c for c in ary(x))

def xor(a, b):
    a, b = map(ary, (a,b))
    return ary([x^y for x, y in zip(ary(a), b)])

aes_sbox = ary(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'.decode('hex')
)

aes_inv_sbox = ary([0]*len(aes_sbox))
for i in range(len(aes_sbox)):
    aes_inv_sbox[aes_sbox[i]] = i

# The Rcon table is used in AES's key schedule (key expansion)
# It's a pre-computed table of exponentation of 2 in AES's finite field
aes_Rcon = ary(
    '8d01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc59139'
    '72e4d3bd61c29f254a943366cc831d3a74e8cb8d01020408102040801b366cd8'
    'ab4d9a2f5ebc63c697356ad4b37dfaefc5913972e4d3bd61c29f254a943366cc'
    '831d3a74e8cb8d01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b3'
    '7dfaefc5913972e4d3bd61c29f254a943366cc831d3a74e8cb8d010204081020'
    '40801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc5913972e4d3bd61c29f'
    '254a943366cc831d3a74e8cb8d01020408102040801b366cd8ab4d9a2f5ebc63'
    'c697356ad4b37dfaefc5913972e4d3bd61c29f254a943366cc831d3a74e8cb'.decode('hex')
)

def galois_multiply(a, b):
    """Galois Field multiplicaiton for AES"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1b
        b >>= 1

    return p & 0xff

# Precompute the multiplication tables for encryption
gf_mul_by_2 = ary([galois_multiply(x, 2) for x in range(256)])
gf_mul_by_3 = ary([galois_multiply(x, 3) for x in range(256)])
# ... for decryption
gf_mul_by_9 = ary([galois_multiply(x, 9) for x in range(256)])
gf_mul_by_11 = ary([galois_multiply(x, 11) for x in range(256)])
gf_mul_by_13 = ary([galois_multiply(x, 13) for x in range(256)])
gf_mul_by_14 = ary([galois_multiply(x, 14) for x in range(256)])

def sub_bytes(block, sbox=aes_sbox):
    block = ary(block)
    for i in xrange(16):
        block[i] = sbox[block[i]]
    return block

def shift_rows(b):
    b = ary(b)
    b[1], b[5], b[9], b[13] = b[5], b[9], b[13], b[1]
    b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
    b[3], b[7], b[11], b[15] = b[15], b[3], b[7], b[11]
    return b

def shift_rows_inv(b):
    b = ary(b)
    b[5], b[9], b[13], b[1] = b[1], b[5], b[9], b[13]
    b[10], b[14], b[2], b[6] = b[2], b[6], b[10], b[14]
    b[15], b[3], b[7], b[11] = b[3], b[7], b[11], b[15]
    return b

def mix_columns(block):
    block = ary(block)
    # Since we're dealing with a transposed matrix, columns are already
    # sequential
    for col in xrange(0, 16, 4):
        v0, v1, v2, v3 = block[col:col + 4]

        block[col] = gf_mul_by_2[v0] ^ v3 ^ v2 ^ gf_mul_by_3[v1]
        block[col + 1] = gf_mul_by_2[v1] ^ v0 ^ v3 ^ gf_mul_by_3[v2]
        block[col + 2] = gf_mul_by_2[v2] ^ v1 ^ v0 ^ gf_mul_by_3[v3]
        block[col + 3] = gf_mul_by_2[v3] ^ v2 ^ v1 ^ gf_mul_by_3[v0]
    return block

def mix_columns_inv(block):
    block = ary(block)
    # Since we're dealing with a transposed matrix, columns are already
    # sequential
    for col in xrange(0, 16, 4):
        v0, v1, v2, v3 = block[col:col + 4]

        block[col] = gf_mul_by_14[v0] ^ gf_mul_by_9[v3] ^ gf_mul_by_13[v2] ^ gf_mul_by_11[v1]
        block[col + 1] = gf_mul_by_14[v1] ^ gf_mul_by_9[v0] ^ gf_mul_by_13[v3] ^ gf_mul_by_11[v2]
        block[col + 2] = gf_mul_by_14[v2] ^ gf_mul_by_9[v1] ^ gf_mul_by_13[v0] ^ gf_mul_by_11[v3]
        block[col + 3] = gf_mul_by_14[v3] ^ gf_mul_by_9[v2] ^ gf_mul_by_13[v1] ^ gf_mul_by_11[v0]
    return block


class AES(object):
    block_size = 16

    def __init__(self, key):
        self.setkey(key)

    def setkey(self, key):
        """Sets the key and performs key expansion."""

        self.key = key
        self.key_size = len(key)

        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            self.rounds = 12
        elif self.key_size == 32:
            self.rounds = 14
        else:
            raise ValueError("Key length must be 16, 24 or 32 bytes")

        self.expand_key()

    def expand_key(self):
        """Performs AES key expansion on self.key and stores in self.exkey"""

        # The expanded key starts with the actual key itself
        exkey = ary(self.key)

        # extra key expansion steps
        if self.key_size == 16:
            extra_cnt = 0
        elif self.key_size == 24:
            extra_cnt = 2
        else:
            extra_cnt = 3

        # 4-byte temporary variable for key expansion
        word = exkey[-4:]
        # Each expansion cycle uses 'i' once for Rcon table lookup
        for i in xrange(1, 11):

            #### key schedule core:
            # left-rotate by 1 byte
            word = word[1:4] + word[0:1]

            # apply S-box to all bytes
            for j in xrange(4):
                word[j] = aes_sbox[word[j]]

            # apply the Rcon table to the leftmost byte
            word[0] ^= aes_Rcon[i]
            #### end key schedule core

            for z in xrange(4):
                for j in xrange(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

            # Last key expansion cycle always finishes here
            if len(exkey) >= (self.rounds + 1) * self.block_size:
                break

            # Special substitution step for 256-bit key
            if self.key_size == 32:
                for j in xrange(4):
                    # mix in bytes from the last subkey XORed with S-box of
                    # current word bytes
                    word[j] = aes_sbox[word[j]] ^ exkey[-self.key_size + j]
                exkey.extend(word)

            # Twice for 192-bit key, thrice for 256-bit key
            for z in xrange(extra_cnt):
                for j in xrange(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

        self.exkey = exkey

    def get_round_key(self, round):
        return [self.exkey[round*16 + i] for i in range(16)]

    def encrypt(self, block):
        block = xor(block, self.get_round_key(0))

        for round in xrange(1, self.rounds):
            block = sub_bytes(block, aes_sbox)
            block = shift_rows(block)
            block = mix_columns(block)
            block = xor(block, self.get_round_key(round))

        block = sub_bytes(block, aes_sbox)
        block = shift_rows(block)
        block = xor(block, self.get_round_key(self.rounds))
        return block

    def decrypt(self, block):
        block = xor(block, self.get_round_key(self.rounds))

        for round in xrange(self.rounds - 1, 0, -1):
            block = shift_rows_inv(block)
            block = sub_bytes(block, aes_inv_sbox)
            block = xor(block, self.get_round_key(round))
            block = mix_columns_inv(block)

        block = shift_rows_inv(block)
        block = sub_bytes(block, aes_inv_sbox)
        block = xor(block, self.get_round_key(0))
        return block

if __name__ == '__main__':
    print 'Running test...'
    import Crypto.Cipher.AES

    key = ''.join(map(chr, range(16)))
    plain = ''.join(map(chr, range(16, 32)))
    assert len(key) == len(plain) == 16

    cipher = AES(key)
    cipher2 = Crypto.Cipher.AES.new(key)
    assert (list(cipher.encrypt(plain))
        == map(ord, cipher2.encrypt(plain)))
    assert (list(cipher.decrypt(plain))
        == map(ord, cipher2.decrypt(plain)))
