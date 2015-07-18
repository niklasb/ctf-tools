def franklin_reiter(a, b, c1, c2, n, e):
    """
    Let ci = mi^e (mod n). Assume m2 = a*m1 + b.
    Returns the tuple (m1, m2).
    """
    def gcd_(a, b):
        if b == 0: return a
        return gcd_(b, a % b)
    RZ.<x> = Integers(n)[]
    g1 = x^e-c1
    g2 = (a*x + b)^e-c2
    c, d = gcd_(g1, g2).coefficients()
    m1 = -c * d^(-1)
    assert pow(m1, e, n) == c1
    assert pow(a*m1 + b, e, n) == c2
    return m1, a*m1 + b

def short_pad(c1, c2, n, e, X=None, epsilon=.1):
    """
    Assume abs(c1 - c2) < X.
    Returns a tuple (m1, m2) with mi^e = ci (mod n).

    Tweak epsilon if no solution is found: smaller is better, but slower.
    """
    if X is None:
        X = floor(n^(1/(e^2)))
    assert X <= n^(1/(e^2))
    RZ.<x,y> = Integers(n)[]
    g1 = x**e - c1
    g2 = (x+y)**e - c2
    h = g1.polynomial(x).resultant(g2.polynomial(x))(y=x).univariate_polynomial()
    # delta = r2 - r1
    delta = h.small_roots(X=X, beta=1, epsilon=epsilon)[0]
    return franklin_reiter(1, delta, c1, c2, n, e)

def factor_lsb(p_lo, mod, upper, n, epsilon=.1):
    """
    Assume n = p*q, p is approximately as large as q, p < upper,
    p = mod * x + p_lo for some integer x, p_lo < mod and mod^2 >= upper
    (i.e. at least half the bits in p are already known)
    Returns p and q.

    Tweak epsilon if no solution is found: smaller is better, but slower.
    """
    assert log(p_lo) >= log(upper) / 2
    Zn = Integers(n)
    RZ.<x> = Zn[]
    f = x + Zn(mod)^(-1)*p_lo
    r = f.small_roots(X=floor((upper - p_lo)/mod), beta=0.4, epsilon=epsilon)[0]
    p = ZZ(r*mod + p_lo)
    assert n % p == 0 and 1 < p < n
    return p, n/p

def factor_msb(p_hi, mod, n, epsilon=.1):
    """
    Assume n = p*q, p is approximately as large as q,
    p = p_hi + x for some integer x < mod and mod < sqrt(p_hi)
    (i.e. at least half the bits in p are already known)
    Returns p and q.

    Tweak epsilon if no solution is found: smaller is better, but slower.
    """
    assert mod <= floor(n^0.5)
    RZ.<x> = Integers(n)[]
    f = p_hi + x
    p_lo = f.small_roots(X=mod, beta=0.4, epsilon=epsilon)[0]
    p = ZZ(p_lo + p_hi)
    assert n % p == 0 and 1 < p < n
    return p, n/p

def broadcast_attack(cs, ns, e):
    """
    Given a list of ciphertexts of the same message under different moduli,
    compute the message.
    """
    assert len(cs) == len(ns) >= e
    assert len(set(ns)) == len(ns)
    m = crt(map(ZZ,cs[:e]), map(ZZ,ns[:e])).nth_root(e)
    assert all(pow(m, e, n) == c for c, n in zip(cs, ns))
    return m

def wiener(e, n):
    """
    Executes a wiener attack on RSA with the given parameters.
    Assume d < n^0.25.
    Returns a tuple (p, q) with p < q and p * q == n or None on failure.
    """
    y = var('y')
    for x in continued_fraction(e / n).convergents():
        k = x.numerator()
        d = x.denominator()
        #print k, d
        if not k: continue
        a = 1
        b = -(n-(e*d-1)/k+1)
        c = n
        disc = b*b-4*a*c
        if disc > 0:
            s = isqrt(disc)
            if s*s != disc: continue
            if (-b - s) % (2*a): continue
            p = (-b - s) // (2*a)
            q = (-b + s) // (2*a)
            if p * q == n:
                return p, q

################# tests #####################

import random

def gen_rsa(bits):
    p = next_prime(random.getrandbits(bits/2))
    q = next_prime(random.getrandbits(bits/2))
    return p, q, p*q

tests = []
def test(f):
    tests.append(f)
    return f

@test
def test_factor_lsb():
    bits = 1024
    p, q, n = gen_rsa(bits)
    mod = 2^(bits/4 + 50)
    pp, qq = factor_lsb(p%mod, mod, 2^(bits/2+1), n)
    assert pp == p and qq == q

@test
def test_factor_msb():
    bits = 1024
    p, q, n = gen_rsa(bits)
    mod = 2^(bits/4 - 50)
    pp, qq = factor_msb(p//mod*mod, mod, n)
    assert pp == p and qq == q

@test
def test_franklin_reiter():
    bits = 1024
    for e in [3, 11, 100]:
        p, q, n = gen_rsa(bits)
        a = random.getrandbits(bits)
        b = random.getrandbits(bits)
        m1 = random.getrandbits(bits)
        m2 = (a * m1 + b) % n
        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)
        mm1, mm2 = franklin_reiter(a, b, c1, c2, n, e)
        assert mm1 == m1 and mm2 == m2

@test
def test_short_pad():
    bits = 1024
    p, q, n = gen_rsa(bits)
    e = 3
    m1 = random.getrandbits(bits)
    m2 = m1 + random.getrandbits(32)
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    mm1, mm2 = short_pad(c1, c2, n, e, X=2^32)
    assert mm1 == m1 and mm2 == m2

@test
def test_broadcast():
    bits = 1024
    e = 5
    m = random.getrandbits(bits - 10)
    cs = []
    ns = []
    for _ in range(e):
        _, _, n = gen_rsa(bits)
        assert m < n
        cs.append(pow(m, e, n))
        ns.append(n)
    assert m == broadcast_attack(cs, ns, e)

@test
def test_wiener():
    p = int(
        '28216117316929874067495888027767527011360661622486842768414'
        '05995157293214519693064136550924376645421851879350884013654'
        '83749940218508532030182057497793903833667618517720550387539'
        '40967432004901699256177783249460134792699230632136386268348'
        '43420301242696312965905778148895006270384944444390661433181'
        '2260961682887')
    q = int(
        '12001304129015480165432875074437607933493850611499879464845'
        '24335021517614476088361532262208144265387264586532699238403'
        '47225862019723921830108134393527782464030168979765715147154'
        '18700569567613729681273931557848857971070286176848136118602'
        '09958610108974323964436734446829596469141142541665251975214'
        '0536869089101')
    assert is_prime(p) and is_prime(q)
    d = int(
        '72474654259001138851336738522869374222274065713748375355231'
        '84332320683703389611452151999945787407890162386559790152245'
        '70943')
    n = p*q
    e = inverse_mod(d, (p-1)*(q-1))
    assert (q, p) == wiener(e, n)

for f in tests:
    print f.func_name
    f()
