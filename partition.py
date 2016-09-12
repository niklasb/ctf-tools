from multiprocessing import Pool
from subprocess import Popen
import argparse
import os
import random
import string
import time
import traceback

def randstr(n):
    alph = (string.ascii_lowercase
            + string.ascii_uppercase
            + string.digits)
    return ''.join(random.choice(alph) for _ in range(n))

def shell_escape(st):
    return "$'%s'" % ''.join(r'\x%02x' % ord(c) for c in st)

def worker((lo, hi, program, outfile, regex)):
    try:
        print 'Processing [%d, %d)' % (lo, hi)
        p = Popen((r'{stdbuf} {program} | '
                   r'{stdbuf} tee {outfile} | '
                   r'sed "s/^\(.*\)/    {lo}-{hi} \1/g" | '
                   r'{stdbuf} egrep --color -e {regex}').format(
                        stdbuf='stdbuf -i0 -o0 -e0',
                        program=program.format(lo, hi),
                        outfile=outfile,
                        regex=shell_escape(regex),
                        lo=lo, hi=hi),
                   shell='/bin/bash')
        p.wait()
    except:
        traceback.print_exc()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('from', type=int, metavar='FROM', help='Start of range (inclusive)')
    p.add_argument('to', type=int, metavar='TO', help='End of range (exclusive)')
    p.add_argument('program', metavar='PROGRAM', help='Worker program')
    p.add_argument('-o', dest='outdir', metavar='DIRECTORY', required=True, help='Output directory')
    p.add_argument('-p', type=int, dest='processes', metavar='PROCS', default=8, help='Number of processes (default = 8)')
    p.add_argument('-r', dest='regex', metavar='REGEX', default='.*', help='Output filter for display')
    args = p.parse_args()

    os.mkdir(args.outdir)
    outdir = args.outdir + '/run_' + time.strftime('%y%m%d_%H%M%S') + '_' + randstr(8)
    print 'Writing to %s' % outdir
    os.mkdir(outdir)

    p = args.processes
    from_ = getattr(args, 'from')
    to = args.to

    pool = Pool(p)
    chunks = []
    start = from_
    tasks = p * 10

    for i in range(tasks):
        size = (to - start + tasks - i - 1) // (tasks - i)
        end = min(to, start + size)
        if start == end: break

        outfile = outdir + '/%d_%d.out' % (start, end)
        chunks.append((start, end, args.program, outfile, args.regex))

        start = end

    pool.map(worker, chunks)
