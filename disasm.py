from tools import *
import argparse

p = argparse.ArgumentParser()
p.add_argument('-32', dest='arch', action='store_const', const=x86, default=x86_64,
        help='Use 32-bit mode')
args = p.parse_args()

arch = args.arch
print arch.disas(sys.stdin.read())
