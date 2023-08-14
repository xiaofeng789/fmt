from pwn import *

#def lg(name,addr):
#    log.info(f'{name} -> {addr}')
#lg(stack,666)

def lg(*args):
    if len(args) >= 2:
        name = args[0]
        addr = args[1]
        log.info(f'{name} -> {addr}')
    else:
        log.error("Insufficient arguments")

lg(stack, 0x666)

