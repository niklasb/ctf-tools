#!/usr/bin/env python2
from tools import *
import argparse

p = argparse.ArgumentParser()
p.add_argument('-32', dest='arch', action='store_const', const=x86, default=x86_64,
        help='Use 32-bit mode')
p.add_argument('-r', dest='raw', action='store_const', const=True, default=False,
        help='Dump raw assembly')
p.add_argument('-d', dest='debug', action='store_const', const=True, default=False,
        help='Show disassembly for debugging')
p.add_argument('asm', metavar='ins', type=str, nargs='+', help='Instructions')
args = p.parse_args()

arch = args.arch
insns = [x for ins in args.asm for x in ins.split(';')]

try:
    sc = arch.assemble('\n'.join(insns))
except:
    sys.exit(1)

if args.debug:
    print arch.disas(sc)
elif args.raw:
    sys.stdout.write(sc)
else:
    print tohex(sc)
