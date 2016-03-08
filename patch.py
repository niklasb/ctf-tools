#!/usr/bin/env python2
from pwnlib.tools import *
import argparse

p = argparse.ArgumentParser()
p.add_argument('-32', dest='arch', action='store_const', const=x86, default=x86_64,
        help='Use 32-bit mode')

p.add_argument('infile', metavar='infile', help='Input file')
p.add_argument('-o', dest='outfile', help='Output file')
p.add_argument('-p', dest='patchfile', help='Patch file')
p.add_argument('patches', metavar='patch', type=str, nargs='*', help='Patch')

args = p.parse_args()
if not args.outfile:
    args.outfile = args.infile + '.patched'
    if os.path.exists(args.outfile):
        sys.stdout.write("Outfile already exists, do you want to override it? [y/N] ")
        answer = raw_input()
        if answer.lower() != 'y':
            sys.exit(1)

patches = args.patches
if args.patchfile:
    with open(args.patchfile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            patches.append(line)
print "Applying %d patches: %s => %s" % (len(patches), args.infile, args.outfile)

with open(args.infile) as f:
    data = f.read()
for p in patches:
    loc, sz, patch = p.split(':', 2)
    loc = int(loc, 16)
    sz = int(sz)
    if loc + sz > len(data):
        print >>sys.stderr, "  Patch location invalid: Input not long enough @ %x" % loc
    if patch == 'nop':
        write = '\x90'*sz
    elif patch.startswith('asm:'):
        write = args.arch.assemble('\n'.join(patch[4:].split(';')))
    else:
        write = patch.decode('hex')
    if len(write) != sz:
        print >>sys.stderr, "  Size mismatch @ %x: Supposed to write %d bytes, but got %d" % (loc, sz, len(write))
        sys.exit(1)
    print "  @ %x-%x: %s" % (loc, loc + sz, write.encode('hex'))
    data = data[:loc] + write + data[loc+sz:]
with open(args.outfile, 'w') as f:
    f.write(data)
