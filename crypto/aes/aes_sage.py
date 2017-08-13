from sage.all import *
from common import *
from aes_py import AES, ary, to_hex, xor, aes_sbox, aes_inv_sbox, aes_Rcon, sub_bytes

F = GF(2)
BF = F['X'];
X, = BF._first_ngens(1)

mod = X**8  + X**4  + X**3  + X + 1
FF = GF(2 ** 8, modulus=mod, names=('A',))
A, = FF._first_ngens(1)

int2ele = FF.fetch_int
ele2int = lambda x: x.integer_representation()

def vec(x):
    return vector(FF, map(int2ele, x))

def idx(c, r):
    return c*4 + r

mix_coeffs = [[2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2]]
MixColumns = matrix(FF, 16, 16)
for c in range(4):
    for r1 in range(4):
        for r2 in range(4):
            MixColumns[idx(c,r1), idx(c,r2)] = int2ele(mix_coeffs[r1][r2])

ShiftRows = matrix(FF, 16, 16)
for c in range(4):
    for r in range(4):
        ShiftRows[idx(c,r), idx((c+r)%4, r)] = 1

def sub_bytes_gf(block, sbox=aes_sbox):
    block = map(ele2int, block)
    return vec(sub_bytes(block, sbox))

def shift_rows_gf(b):
    return ShiftRows * b

def shift_rows_inv_gf(b):
    return ShiftRows**(-1) * b

def mix_columns_gf(b):
    return MixColumns * b

def mix_columns_inv_gf(b):
    return MixColumns**(-1) * b

class AES_GF(AES):
    def get_round_key_gf(self, round):
        return vec(self.get_round_key(round))

    def encrypt(self, block):
        block += self.get_round_key_gf(0)

        for round in xrange(1, self.rounds):
            block = sub_bytes_gf(block, aes_sbox)
            block = shift_rows_gf(block)
            block = mix_columns_gf(block)
            block += self.get_round_key_gf(round)

        block = sub_bytes_gf(block, aes_sbox)
        block = shift_rows_gf(block)
        block += self.get_round_key_gf(self.rounds)
        return block

    def decrypt(self, block):
        block += self.get_round_key_gf(self.rounds)

        for round in xrange(self.rounds - 1, 0, -1):
            block = shift_rows_inv_gf(block)
            block = sub_bytes_gf(block, aes_inv_sbox)
            block += self.get_round_key_gf(round)
            block = mix_columns_inv_gf(block)

        block = shift_rows_inv_gf(block)
        block = sub_bytes_gf(block, aes_inv_sbox)
        block += self.get_round_key_gf(0)
        return block

if __name__ == '__main__':
    print 'Running test...'
    import Crypto.Cipher.AES

    key = ''.join(map(chr, range(16)))
    plain = ''.join(map(chr, range(16, 32)))
    assert len(key) == len(plain) == 16

    cipher = AES_GF(key)
    cipher2 = Crypto.Cipher.AES.new(key)
    assert (map(ele2int, cipher.encrypt(vec(ary(plain))))
        == map(ord, cipher2.encrypt(plain)))
    assert (map(ele2int, cipher.decrypt(vec(ary(plain))))
        == map(ord, cipher2.decrypt(plain)))
