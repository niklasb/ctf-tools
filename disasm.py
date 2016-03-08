#!/usr/bin/env python2
from tools import *
import argparse

p = argparse.ArgumentParser()
p.add_argument('-32', dest='arch', action='store_const', const=x86, default=x86_64,
        help='Use 32-bit mode')
p.add_argument('asm', metavar='code', type=str, nargs='*', help='Code')
args = p.parse_args()

arch = args.arch
if args.asm:
    code = ''.join(args.asm).decode('hex')
else:
    code = sys.stdin.read()
print arch.disas(code)
