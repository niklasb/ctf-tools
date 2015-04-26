import struct
import hashlib
import requests
import urllib

md5_iv = (0x67452301L,0xefcdab89L,0x98badcfeL,0x10325476L)

def unpack_state(state):
    return struct.unpack("IIII", state)

def pack_state(state):
    return struct.pack("IIII", *state)

# below functions taken from http://python.net/~gherman/programs/md5py/md5py.py
def F(x, y, z):
    return (x & y) | ((~x) & z)

def G(x, y, z):
    return (x & z) | (y & (~z))

def H(x, y, z):
    return x ^ y ^ z

def I(x, y, z):
    return y ^ (x | (~z))

def _rotateLeft(x, n):
    return (x << n) | (x >> (32-n))

def XX(func, a, b, c, d, x, s, ac):
    res = 0L
    res = res + a + func(b, c, d)
    res = res + x
    res = res + ac
    res = res & 0xffffffffL
    res = _rotateLeft(res, s)
    res = res & 0xffffffffL
    res = res + b

    return res & 0xffffffffL

def md5_compress(state, buf):
    if len(buf) != 64:
        raise ValueError, "Invalid buffer of length %d: %s" % (len(buf), repr(buf))
    inp = struct.unpack("I"*16, buf)
    a, b, c, d = A, B, C, D = state

    # Round 1.
    S11, S12, S13, S14 = 7, 12, 17, 22

    a = XX(F, a, b, c, d, inp[ 0], S11, 0xD76AA478L) # 1
    d = XX(F, d, a, b, c, inp[ 1], S12, 0xE8C7B756L) # 2
    c = XX(F, c, d, a, b, inp[ 2], S13, 0x242070DBL) # 3
    b = XX(F, b, c, d, a, inp[ 3], S14, 0xC1BDCEEEL) # 4
    a = XX(F, a, b, c, d, inp[ 4], S11, 0xF57C0FAFL) # 5
    d = XX(F, d, a, b, c, inp[ 5], S12, 0x4787C62AL) # 6
    c = XX(F, c, d, a, b, inp[ 6], S13, 0xA8304613L) # 7
    b = XX(F, b, c, d, a, inp[ 7], S14, 0xFD469501L) # 8
    a = XX(F, a, b, c, d, inp[ 8], S11, 0x698098D8L) # 9
    d = XX(F, d, a, b, c, inp[ 9], S12, 0x8B44F7AFL) # 10
    c = XX(F, c, d, a, b, inp[10], S13, 0xFFFF5BB1L) # 11
    b = XX(F, b, c, d, a, inp[11], S14, 0x895CD7BEL) # 12
    a = XX(F, a, b, c, d, inp[12], S11, 0x6B901122L) # 13
    d = XX(F, d, a, b, c, inp[13], S12, 0xFD987193L) # 14
    c = XX(F, c, d, a, b, inp[14], S13, 0xA679438EL) # 15
    b = XX(F, b, c, d, a, inp[15], S14, 0x49B40821L) # 16

    # Round 2.
    S21, S22, S23, S24 = 5, 9, 14, 20

    a = XX(G, a, b, c, d, inp[ 1], S21, 0xF61E2562L) # 17
    d = XX(G, d, a, b, c, inp[ 6], S22, 0xC040B340L) # 18
    c = XX(G, c, d, a, b, inp[11], S23, 0x265E5A51L) # 19
    b = XX(G, b, c, d, a, inp[ 0], S24, 0xE9B6C7AAL) # 20
    a = XX(G, a, b, c, d, inp[ 5], S21, 0xD62F105DL) # 21
    d = XX(G, d, a, b, c, inp[10], S22, 0x02441453L) # 22
    c = XX(G, c, d, a, b, inp[15], S23, 0xD8A1E681L) # 23
    b = XX(G, b, c, d, a, inp[ 4], S24, 0xE7D3FBC8L) # 24
    a = XX(G, a, b, c, d, inp[ 9], S21, 0x21E1CDE6L) # 25
    d = XX(G, d, a, b, c, inp[14], S22, 0xC33707D6L) # 26
    c = XX(G, c, d, a, b, inp[ 3], S23, 0xF4D50D87L) # 27
    b = XX(G, b, c, d, a, inp[ 8], S24, 0x455A14EDL) # 28
    a = XX(G, a, b, c, d, inp[13], S21, 0xA9E3E905L) # 29
    d = XX(G, d, a, b, c, inp[ 2], S22, 0xFCEFA3F8L) # 30
    c = XX(G, c, d, a, b, inp[ 7], S23, 0x676F02D9L) # 31
    b = XX(G, b, c, d, a, inp[12], S24, 0x8D2A4C8AL) # 32

    # Round 3.
    S31, S32, S33, S34 = 4, 11, 16, 23

    a = XX(H, a, b, c, d, inp[ 5], S31, 0xFFFA3942L) # 33
    d = XX(H, d, a, b, c, inp[ 8], S32, 0x8771F681L) # 34
    c = XX(H, c, d, a, b, inp[11], S33, 0x6D9D6122L) # 35
    b = XX(H, b, c, d, a, inp[14], S34, 0xFDE5380CL) # 36
    a = XX(H, a, b, c, d, inp[ 1], S31, 0xA4BEEA44L) # 37
    d = XX(H, d, a, b, c, inp[ 4], S32, 0x4BDECFA9L) # 38
    c = XX(H, c, d, a, b, inp[ 7], S33, 0xF6BB4B60L) # 39
    b = XX(H, b, c, d, a, inp[10], S34, 0xBEBFBC70L) # 40
    a = XX(H, a, b, c, d, inp[13], S31, 0x289B7EC6L) # 41
    d = XX(H, d, a, b, c, inp[ 0], S32, 0xEAA127FAL) # 42
    c = XX(H, c, d, a, b, inp[ 3], S33, 0xD4EF3085L) # 43
    b = XX(H, b, c, d, a, inp[ 6], S34, 0x04881D05L) # 44
    a = XX(H, a, b, c, d, inp[ 9], S31, 0xD9D4D039L) # 45
    d = XX(H, d, a, b, c, inp[12], S32, 0xE6DB99E5L) # 46
    c = XX(H, c, d, a, b, inp[15], S33, 0x1FA27CF8L) # 47
    b = XX(H, b, c, d, a, inp[ 2], S34, 0xC4AC5665L) # 48

    # Round 4.
    S41, S42, S43, S44 = 6, 10, 15, 21

    a = XX(I, a, b, c, d, inp[ 0], S41, 0xF4292244L) # 49
    d = XX(I, d, a, b, c, inp[ 7], S42, 0x432AFF97L) # 50
    c = XX(I, c, d, a, b, inp[14], S43, 0xAB9423A7L) # 51
    b = XX(I, b, c, d, a, inp[ 5], S44, 0xFC93A039L) # 52
    a = XX(I, a, b, c, d, inp[12], S41, 0x655B59C3L) # 53
    d = XX(I, d, a, b, c, inp[ 3], S42, 0x8F0CCC92L) # 54
    c = XX(I, c, d, a, b, inp[10], S43, 0xFFEFF47DL) # 55
    b = XX(I, b, c, d, a, inp[ 1], S44, 0x85845DD1L) # 56
    a = XX(I, a, b, c, d, inp[ 8], S41, 0x6FA87E4FL) # 57
    d = XX(I, d, a, b, c, inp[15], S42, 0xFE2CE6E0L) # 58
    c = XX(I, c, d, a, b, inp[ 6], S43, 0xA3014314L) # 59
    b = XX(I, b, c, d, a, inp[13], S44, 0x4E0811A1L) # 60
    a = XX(I, a, b, c, d, inp[ 4], S41, 0xF7537E82L) # 61
    d = XX(I, d, a, b, c, inp[11], S42, 0xBD3AF235L) # 62
    c = XX(I, c, d, a, b, inp[ 2], S43, 0x2AD7D2BBL) # 63
    b = XX(I, b, c, d, a, inp[ 9], S44, 0xEB86D391L) # 64

    A = (A + a) & 0xffffffffL
    B = (B + b) & 0xffffffffL
    C = (C + c) & 0xffffffffL
    D = (D + d) & 0xffffffffL

    return (A, B, C, D)

def padding(n, sz=None):
    if sz is None:
        sz = n
    pre = 64-8
    sz = struct.pack("Q",sz*8)
    pad = chr(0b10000000)
    n += 1
    if n % 64 <= pre:
        pad += '\0' * (pre - n % 64)
        pad += sz
    else:
        pad += '\0' * (pre + 64 - n % 64)
        pad += sz
    return pad

def pad(msg):
    return msg + padding(len(msg))

def md5_iter(msg, state):
    assert len(msg) % 64 == 0
    for i in range(0, len(msg), 64):
        block = msg[i:i+64]
        state = md5_compress(state, msg[i:i+64])
    return state

def my_md5(msg):
    return pack_state(md5_iter(pad(msg), md5_iv))

def md5(msg):
    return hashlib.md5(msg).digest()

def extend_hash(s1, m1, m2, prefsz):
    """ Given a hash s1 := md5(prefix + m1) and the length of prefix, compute
    s2 := md5(prefix + m1 + padding(prefix + m1) + m2).

    Returns the pair (s2, m1 + padding(prefix + m1) + m2)
    """
    p = padding(prefsz + len(m1))
    s2 = md5_iter(m2 + padding(len(m2), prefsz + len(m1 + p + m2)), unpack_state(s1))
    return (pack_state(s2), m1 + p + m2)

def test():
    for i in range(100):
        s = "A"*i
        assert md5(s) == my_md5(s)
    for i in range(50):
        prefix = "A"*i
        for j in range(100):
            m1 = "B"*j
            m2 = "C"*j
            s1 = md5(prefix + m1)
            s2, msg = extend_hash(s1, m1, m2, len(prefix))
            assert msg.startswith(m1) and msg.endswith(m2)
            assert s2 == md5(prefix + msg)
test()
