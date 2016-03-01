#!/usr/bin/env python2
from tools import *
a = sys.argv
def i(x):
    return int(x[2:],16) if x.startswith('0x') else int(x)
n = i(a[1]) if len(a) > 1 else 0x400
p = Pattern(n)
if len(a) <= 2:
    print str(p)
elif len(a[2]) <= 4:
    print p.offset(a[2])
else:
    print p.offset(i(a[2]))
