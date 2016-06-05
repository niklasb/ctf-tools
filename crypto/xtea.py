"""
A hackable XTEA implementation. From Wikipedia

#include <stdint.h>

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
"""

rounds = 128
mask = 0xffffffff
delta = 0x9E3779B9
def encrypt(v, key):
    v=list(v)
    sum = 0
    v7 = ley[0]
    for _ in range(rounds):
        v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
        v[0] &= mask
        sum = (sum+delta) & mask
        v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum>>11) & 3]);
        v[1] &= mask
    return v

def decrypt(v, key):
    v=list(v)
    sum=(delta*rounds)&mask
    for _ in range(rounds):
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum>>11) & 3])
        v[1] &= mask
        sum = (sum-delta)&mask
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3])
        v[0] &= mask
    return v
